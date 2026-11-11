using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sour.Core
{
    /// <summary>Folders used by Sour. Everything lives under %LOCALAPPDATA%\Sour; nothing is written elsewhere
    /// except canary files (ransomware shield, only when the user turns it on).</summary>
    public static class Paths
    {
        public static string OverrideRoot;   // tests point this at a scratch folder

        public static string Root
        {
            get
            {
                string r = OverrideRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sour");
                Directory.CreateDirectory(r);
                return r;
            }
        }
        public static string Sub(string name) { string p = Path.Combine(Root, name); Directory.CreateDirectory(p); return p; }
        public static string SettingsFile => Path.Combine(Root, "settings.json");
        public static string RulesFile => Path.Combine(Root, "firewall_rules.json");
        public static string EventsFile => Path.Combine(Root, "events.jsonl");
        public static string ProfilesFile => Path.Combine(Root, "net_profiles.json");
        public static string HashDbFile => Path.Combine(Root, "hashes_user.txt");
        public static string ScanCacheFile => Path.Combine(Root, "scan_cache.json");
        public static string Quarantine => Sub("Quarantine");
        public static string AppDir => AppContext.BaseDirectory;
        public static string DataDir => Path.Combine(AppDir, "Data");
    }

    public static class Json
    {
        public static readonly JsonSerializerOptions Opt = new JsonSerializerOptions
        {
            WriteIndented = true,
            IncludeFields = true,
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Converters = { new JsonStringEnumConverter() },
        };
        public static readonly JsonSerializerOptions Line = new JsonSerializerOptions(Opt) { WriteIndented = false };

        public static T Load<T>(string file) where T : new()
        {
            try
            {
                if (File.Exists(file)) return JsonSerializer.Deserialize<T>(File.ReadAllText(file, Encoding.UTF8), Opt) ?? new T();
            }
            catch (Exception ex) { Log.Debug("json load " + file + ": " + ex.Message); }
            return new T();
        }

        /// <summary>Atomic save: write to a temp file, then replace.</summary>
        public static void Save<T>(string file, T value)
        {
            string tmp = file + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(value, Opt), new UTF8Encoding(false));
            File.Move(tmp, file, true);
        }
    }

    public enum Severity { Info, Low, Medium, High, Critical }
    public enum EventKind { System, Firewall, Antivirus, Ransomware, Network, Ai, Persistence }

    public sealed class SecEvent
    {
        public DateTime Time = DateTime.Now;
        public EventKind Kind;
        public Severity Level;
        public string Code;      // stable machine code, e.g. "fw.blocked"
        public string TitleEn, TitleAr;
        public string Detail;    // evidence: path, address, rule, score
        public string Subject;   // file path or process path the event is about

        [JsonIgnore] public string Title => I18n.IsArabic && !string.IsNullOrEmpty(TitleAr) ? TitleAr : TitleEn;
    }

    /// <summary>In-memory + on-disk security event journal (JSON lines, capped).</summary>
    public static class Log
    {
        static readonly object Gate = new object();
        static readonly List<SecEvent> Mem = new List<SecEvent>();
        public static event Action<SecEvent> Added;
        public static bool Persist = true;
        const int MemCap = 3000;

        public static void Debug(string msg) { System.Diagnostics.Debug.WriteLine("[sour] " + msg); }

        public static SecEvent Add(EventKind kind, Severity level, string code, string en, string ar, string detail = null, string subject = null)
        {
            var e = new SecEvent { Kind = kind, Level = level, Code = code, TitleEn = en, TitleAr = ar, Detail = detail, Subject = subject };
            lock (Gate)
            {
                Mem.Add(e);
                if (Mem.Count > MemCap) Mem.RemoveRange(0, Mem.Count - MemCap);
                if (Persist)
                {
                    try { File.AppendAllText(Paths.EventsFile, JsonSerializer.Serialize(e, Json.Line) + "\n", new UTF8Encoding(false)); }
                    catch { }
                }
            }
            try { Added?.Invoke(e); } catch { }
            return e;
        }

        public static List<SecEvent> Snapshot() { lock (Gate) return new List<SecEvent>(Mem); }

        public static void LoadFromDisk(int max = 1500)
        {
            try
            {
                if (!File.Exists(Paths.EventsFile)) return;
                var fi = new FileInfo(Paths.EventsFile);
                if (fi.Length > 8 * 1024 * 1024)   // rotate
                {
                    var keep = File.ReadLines(Paths.EventsFile).Reverse().Take(max).Reverse().ToArray();
                    File.WriteAllLines(Paths.EventsFile, keep, new UTF8Encoding(false));
                }
                var lines = File.ReadLines(Paths.EventsFile).Reverse().Take(max).Reverse();
                lock (Gate)
                {
                    foreach (var l in lines)
                    {
                        try { var e = JsonSerializer.Deserialize<SecEvent>(l, Json.Line); if (e != null) Mem.Add(e); } catch { }
                    }
                }
            }
            catch { }
        }

        public static void Clear()
        {
            lock (Gate) { Mem.Clear(); try { File.Delete(Paths.EventsFile); } catch { } }
        }
    }

    public static class Util
    {
        public static bool IsAdmin()
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        public static string Sha256(string file)
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
        }

        public static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

        public static double Entropy(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0) return 0;
            Span<int> c = stackalloc int[256];
            foreach (byte b in data) c[b]++;
            double h = 0, n = data.Length;
            for (int i = 0; i < 256; i++) if (c[i] > 0) { double p = c[i] / n; h -= p * Math.Log2(p); }
            return h;
        }

        public static string HumanSize(long b)
        {
            string[] u = { "B", "KB", "MB", "GB", "TB" };
            double v = b; int i = 0;
            while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
            return v.ToString(i == 0 ? "0" : "0.0", System.Globalization.CultureInfo.InvariantCulture) + " " + u[i];
        }

        /// <summary>Run a console tool hidden and capture its output. Used for auditpol/schtasks only.</summary>
        public static (int code, string output) Run(string exe, string args, int timeoutMs = 20000)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                };
                using var p = Process.Start(psi);
                string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } return (-2, o); }
                return (p.ExitCode, o);
            }
            catch (Exception ex) { return (-1, ex.Message); }
        }

        public static bool RestartElevated(string args = "")
        {
            try
            {
                var psi = new ProcessStartInfo(Environment.ProcessPath, args) { UseShellExecute = true, Verb = "runas" };
                Process.Start(psi);
                return true;
            }
            catch { return false; }   // user declined the UAC prompt
        }

        /// <summary>Left-to-right embedding so paths and IPs read correctly inside Arabic text.</summary>
        public static string Ltr(string s) => string.IsNullOrEmpty(s) ? s : "‪" + s + "‬";
    }
}
