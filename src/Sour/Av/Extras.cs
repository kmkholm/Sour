using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sour.Core;

namespace Sour.Av
{
    public sealed class BrowserExtension
    {
        public string Browser, Profile, Id, Name, Version, Folder;
        public List<string> Permissions = new List<string>();
        public bool AllSites;
        public int Risk;                 // 0 low, 1 medium, 2 high
        public string Why = "";
    }

    public sealed class LanDevice
    {
        public string Ip, Mac; public bool Gateway; public bool IsNew;
    }

    public sealed class KnownDevices { public Dictionary<string, DateTime> Macs = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase); }

    /// <summary>Additional inspections: browser extensions, devices on the local network, secure file deletion.</summary>
    public static class Extras
    {
        // ------------------------------------------------------------------ browser extensions
        static readonly string[] Sensitive = { "webRequest", "webRequestBlocking", "cookies", "scripting", "debugger", "nativeMessaging", "clipboardRead", "proxy", "management", "history", "downloads", "tabs", "declarativeNetRequest", "privacy" };
        static readonly string[] Broad = { "<all_urls>", "*://*/*", "http://*/*", "https://*/*" };

        public static IEnumerable<(string browser, string userData)> BrowserRoots()
        {
            string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            yield return ("Chrome", Path.Combine(la, "Google\\Chrome\\User Data"));
            yield return ("Edge", Path.Combine(la, "Microsoft\\Edge\\User Data"));
            yield return ("Brave", Path.Combine(la, "BraveSoftware\\Brave-Browser\\User Data"));
        }

        /// <summary>Lists installed extensions of Chromium browsers and rates how much each one can see and change.</summary>
        public static List<BrowserExtension> BrowserExtensions(IEnumerable<(string browser, string userData)> roots = null)
        {
            var res = new List<BrowserExtension>();
            foreach (var (browser, userData) in roots ?? BrowserRoots())
            {
                if (!Directory.Exists(userData)) continue;
                IEnumerable<string> profiles;
                try { profiles = Directory.GetDirectories(userData).Where(d => { string n = Path.GetFileName(d); return n == "Default" || n.StartsWith("Profile "); }); } catch { continue; }
                foreach (string profile in profiles)
                {
                    string extRoot = Path.Combine(profile, "Extensions");
                    if (!Directory.Exists(extRoot)) continue;
                    foreach (string idDir in Directory.GetDirectories(extRoot))
                    {
                        try
                        {
                            string verDir = Directory.GetDirectories(idDir).OrderByDescending(d => d).FirstOrDefault();
                            string manifest = verDir == null ? null : Path.Combine(verDir, "manifest.json");
                            if (manifest == null || !File.Exists(manifest)) continue;
                            var e = ParseManifest(manifest);
                            e.Browser = browser; e.Profile = Path.GetFileName(profile); e.Id = Path.GetFileName(idDir); e.Folder = verDir;
                            res.Add(e);
                        }
                        catch { }
                    }
                }
            }
            return res.OrderByDescending(e => e.Risk).ThenBy(e => e.Browser).ThenBy(e => e.Name).ToList();
        }

        public static BrowserExtension ParseManifest(string manifestPath)
        {
            var e = new BrowserExtension();
            using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            var root = doc.RootElement;
            e.Name = root.TryGetProperty("name", out var n) ? n.GetString() : "?";
            e.Version = root.TryGetProperty("version", out var v) ? v.GetString() : "";
            if (e.Name != null && e.Name.StartsWith("__MSG_"))
            {
                string key = e.Name.Substring(6).TrimEnd('_');
                string locale = root.TryGetProperty("default_locale", out var dl) ? dl.GetString() : "en";
                foreach (string loc in new[] { locale, "en", "en_US" })
                {
                    string mf = Path.Combine(Path.GetDirectoryName(manifestPath), "_locales", loc ?? "en", "messages.json");
                    if (!File.Exists(mf)) continue;
                    try
                    {
                        using var md = JsonDocument.Parse(File.ReadAllText(mf), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                        foreach (var p in md.RootElement.EnumerateObject())
                            if (string.Equals(p.Name, key, StringComparison.OrdinalIgnoreCase) && p.Value.TryGetProperty("message", out var msg)) { e.Name = msg.GetString(); break; }
                    }
                    catch { }
                    if (!e.Name.StartsWith("__MSG_")) break;
                }
            }
            var hosts = new List<string>();
            void Collect(string prop)
            {
                if (!root.TryGetProperty(prop, out var arr) || arr.ValueKind != JsonValueKind.Array) return;
                foreach (var x in arr.EnumerateArray())
                {
                    if (x.ValueKind != JsonValueKind.String) continue;
                    string s = x.GetString();
                    if (s.Contains("://") || s == "<all_urls>") hosts.Add(s); else e.Permissions.Add(s);
                }
            }
            Collect("permissions"); Collect("host_permissions"); Collect("optional_host_permissions");
            if (root.TryGetProperty("content_scripts", out var cs) && cs.ValueKind == JsonValueKind.Array)
                foreach (var c in cs.EnumerateArray())
                    if (c.TryGetProperty("matches", out var m) && m.ValueKind == JsonValueKind.Array)
                        foreach (var x in m.EnumerateArray()) if (x.ValueKind == JsonValueKind.String) hosts.Add(x.GetString());
            e.AllSites = hosts.Any(h => Broad.Contains(h));
            var sens = e.Permissions.Where(p => Sensitive.Contains(p)).Distinct().ToList();
            bool strong = sens.Any(p => p != "tabs" && p != "downloads" && p != "declarativeNetRequest");
            e.Risk = e.AllSites && strong ? 2 : e.AllSites || sens.Contains("nativeMessaging") || sens.Contains("debugger") ? 1 : 0;
            var why = new List<string>();
            if (e.AllSites) why.Add(I18n.T("reads and changes every website", "يقرأ ويغيّر كل المواقع"));
            if (sens.Count > 0) why.Add(string.Join(", ", sens));
            e.Why = string.Join(" · ", why);
            return e;
        }

        // ------------------------------------------------------------------ devices on the local network
        static readonly Regex ArpLine = new Regex(@"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s", RegexOptions.Compiled);
        static string KnownFile => Path.Combine(Paths.Root, "lan_devices.json");

        public static List<LanDevice> ParseArp(string text, HashSet<string> gateways)
        {
            var res = new Dictionary<string, LanDevice>(StringComparer.OrdinalIgnoreCase);
            foreach (string line in text.Split('\n'))
            {
                var m = ArpLine.Match(line);
                if (!m.Success) continue;
                string ip = m.Groups[1].Value, mac = m.Groups[2].Value.ToLowerInvariant();
                int first = int.Parse(ip.Split('.')[0]);
                if (first >= 224 || mac == "ff-ff-ff-ff-ff-ff" || mac.StartsWith("01-00-5e")) continue;      // multicast / broadcast
                res[mac] = new LanDevice { Ip = ip, Mac = mac, Gateway = gateways != null && gateways.Contains(ip) };
            }
            return res.Values.OrderByDescending(d => d.Gateway).ThenBy(d => Version.TryParse(d.Ip, out var v) ? v : new Version()).ToList();
        }

        /// <summary>Neighbours this PC has talked to (the ARP cache). Devices never seen before are marked new.</summary>
        public static List<LanDevice> LanDevices(bool remember = true)
        {
            var gw = new HashSet<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up))
                    foreach (var g in ni.GetIPProperties().GatewayAddresses) gw.Add(g.Address.ToString());
            }
            catch { }
            var list = ParseArp(Util.Run("arp.exe", "-a", 8000).output, gw);
            var known = Json.Load<KnownDevices>(KnownFile);
            bool firstRun = known.Macs.Count == 0;
            foreach (var d in list)
            {
                d.IsNew = !firstRun && !known.Macs.ContainsKey(d.Mac);
                if (remember && !known.Macs.ContainsKey(d.Mac)) known.Macs[d.Mac] = DateTime.Now;
            }
            if (remember) { try { Json.Save(KnownFile, known); } catch { } }
            return list;
        }

        // ------------------------------------------------------------------ secure delete
        /// <summary>
        /// Overwrites a file with random data, renames it and deletes it. On hard disks the old content is gone;
        /// on SSDs wear-levelling may keep stale blocks, so this is "hard to recover", not a forensic guarantee.
        /// </summary>
        public static (bool ok, string error) Shred(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return (false, "not found");
                File.SetAttributes(path, FileAttributes.Normal);
                long len = fi.Length;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None, 1 << 16, FileOptions.WriteThrough))
                {
                    var buf = new byte[1 << 16];
                    for (long done = 0; done < len;)
                    {
                        RandomNumberGenerator.Fill(buf);
                        int n = (int)Math.Min(buf.Length, len - done);
                        fs.Write(buf, 0, n); done += n;
                    }
                    fs.Flush(true);
                }
                string anon = Path.Combine(Path.GetDirectoryName(path), Guid.NewGuid().ToString("N"));
                File.Move(path, anon);
                File.Delete(anon);
                return (true, null);
            }
            catch (Exception ex) { return (false, ex.Message); }
        }
    }
}
