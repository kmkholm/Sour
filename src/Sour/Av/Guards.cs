using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using Sour.Core;

namespace Sour.Av
{
    public sealed class Detection
    {
        public string Id = Guid.NewGuid().ToString("N");
        public ScanResult Result; public string Source; public DateTime Time = DateTime.Now;
        public int Pid;                 // set when the detection is a running process (kept suspended)
        public string State = "pending";
    }

    /// <summary>Native helpers for inspecting and freezing other processes.</summary>
    public static class Proc
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
        [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr h);
        [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, IntPtr buf, int len, out int ret);
        [DllImport("kernel32.dll")] static extern bool GetProcessIoCounters(IntPtr h, out IO_COUNTERS c);
        [StructLayout(LayoutKind.Sequential)] public struct IO_COUNTERS { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }

        public static bool Suspend(int pid) => With(pid, 0x0800, h => NtSuspendProcess(h) == 0);
        public static bool Resume(int pid) => With(pid, 0x0800, h => NtResumeProcess(h) == 0);
        public static bool Kill(int pid) { try { Process.GetProcessById(pid).Kill(true); return true; } catch { return false; } }

        static bool With(int pid, uint access, Func<IntPtr, bool> f)
        {
            IntPtr h = OpenProcess(access, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return f(h); } finally { CloseHandle(h); }
        }

        public static ulong WriteBytes(int pid)
        {
            ulong w = 0;
            With(pid, 0x1000, h => { if (GetProcessIoCounters(h, out var c)) w = c.WriteBytes; return true; });
            return w;
        }

        /// <summary>Command line of another process (ProcessCommandLineInformation, works for same-user processes).</summary>
        public static string CommandLine(int pid)
        {
            string res = null;
            With(pid, 0x1000, h =>
            {
                NtQueryInformationProcess(h, 60, IntPtr.Zero, 0, out int need);
                if (need <= 0 || need > 1 << 20) return false;
                IntPtr buf = Marshal.AllocHGlobal(need);
                try
                {
                    if (NtQueryInformationProcess(h, 60, buf, need, out _) != 0) return false;
                    ushort len = (ushort)Marshal.ReadInt16(buf);            // UNICODE_STRING { Length, MaximumLength, Buffer }
                    IntPtr str = Marshal.ReadIntPtr(buf, IntPtr.Size);
                    if (str != IntPtr.Zero && len > 0) res = Marshal.PtrToStringUni(str, len / 2);
                    return true;
                }
                finally { Marshal.FreeHGlobal(buf); }
            });
            return res;
        }
    }

    /// <summary>
    /// Live protection: file guard, process guard, ransomware shield, USB guard and persistence watch.
    /// No kernel driver is used, so files are examined right after they are written (not before) and a process
    /// is examined right after it starts; a malicious process is frozen (suspended) until the user decides.
    /// </summary>
    public sealed class Guard
    {
        public static readonly Guard Instance = new Guard();

        public readonly List<Detection> Pending = new List<Detection>();
        public event Action<Detection> Detected;
        public event Action StateChanged;
        public long RealtimeScans;

        readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        readonly ConcurrentDictionary<string, DateTime> _queue = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        Timer _fileTimer, _procTimer, _slowTimer;
        readonly HashSet<int> _knownPids = new HashSet<int>();
        bool _procPrimed;

        public bool FileGuardOn => _watchers.Count > 0;
        public bool ProcessGuardOn => _procTimer != null;
        public bool RansomShieldOn => _ransomWatchers.Count > 0;

        /// <summary>Starts/stops every guard so that it matches the settings.</summary>
        public void Sync()
        {
            var s = Settings.Current;
            if (s.AvRealtime && !FileGuardOn) StartFileGuard(); else if (!s.AvRealtime && FileGuardOn) StopFileGuard();
            if (s.AvProcessWatch && !ProcessGuardOn) { _procPrimed = false; _procTimer = new Timer(_ => Safe(ProcessTick), null, 500, 1500); }
            else if (!s.AvProcessWatch && ProcessGuardOn) { _procTimer.Dispose(); _procTimer = null; }
            if (s.AvRansomShield && !RansomShieldOn) StartRansomShield(); else if (!s.AvRansomShield && RansomShieldOn) StopRansomShield();
            bool slow = s.AvUsbScan || s.AvPersistenceWatch || s.AvRansomShield;
            if (slow && _slowTimer == null) _slowTimer = new Timer(_ => Safe(SlowTick), null, 2000, 3000);
            else if (!slow && _slowTimer != null) { _slowTimer.Dispose(); _slowTimer = null; }
            StateChanged?.Invoke();
        }

        public void StopAll()
        {
            StopFileGuard(); StopRansomShield();
            _procTimer?.Dispose(); _procTimer = null; _slowTimer?.Dispose(); _slowTimer = null;
        }

        static void Safe(Action a) { try { a(); } catch (Exception ex) { Log.Debug("guard: " + ex.Message); } }

        // ------------------------------------------------------------------ detections
        public Detection Handle(ScanResult r, string source, int pid = 0)
        {
            var d = new Detection { Result = r, Source = source, Pid = pid };
            var sev = r.Verdict == Verdict.Malicious ? Severity.Critical : Severity.Medium;
            Log.Add(EventKind.Antivirus, sev, r.Verdict == Verdict.Malicious ? "av.malicious" : "av.suspicious",
                $"{(r.Verdict == Verdict.Malicious ? "Threat" : "Suspicious file")} found ({source}): {r.Threat}",
                $"{(r.Verdict == Verdict.Malicious ? "تهديد" : "ملف مشبوه")} ({SourceAr(source)}): {r.Threat}",
                $"{r.Path}\nscore {r.Score} · {string.Join(" | ", r.Reasons.OrderByDescending(x => x.Weight).Take(5).Select(x => x.En))}", r.Path);

            var policy = Settings.Current.AvOnMalicious;
            if (r.Verdict == Verdict.Malicious && policy == AvAction.Quarantine)
            {
                if (pid != 0) Proc.Kill(pid);
                var q = Quarantine.Add(r);
                d.State = q.ok ? "quarantined" : "failed: " + q.error;
            }
            else if (policy == AvAction.ReportOnly) { d.State = "reported"; if (pid != 0) Proc.Resume(pid); }
            lock (Pending) { Pending.Add(d); if (Pending.Count > 500) Pending.RemoveAt(0); }
            try { Detected?.Invoke(d); } catch { }
            return d;
        }

        static string SourceAr(string s) => s switch
        {
            "file guard" => "حارس الملفات", "process guard" => "حارس العمليات", "usb" => "وسيط USB", "startup" => "بدء التشغيل",
            "scan" => "فحص", "ransom shield" => "درع الفدية", _ => s,
        };

        public void Resolve(Detection d, string action)
        {
            if (action == "quarantine")
            {
                if (d.Pid != 0) Proc.Kill(d.Pid);
                var q = Quarantine.Add(d.Result);
                d.State = q.ok ? "quarantined" : "failed: " + q.error;
            }
            else if (action == "allow")
            {
                if (d.Pid != 0) Proc.Resume(d.Pid);
                string dir = d.Result.Path;
                if (!Settings.Current.AvExclusions.Contains(dir, StringComparer.OrdinalIgnoreCase)) { Settings.Current.AvExclusions.Add(dir); Settings.Save(); }
                d.State = "allowed";
            }
            else if (action == "ignore") { if (d.Pid != 0) Proc.Resume(d.Pid); d.State = "ignored"; }
            StateChanged?.Invoke();
        }

        // ------------------------------------------------------------------ file guard
        public static List<string> WatchFolders()
        {
            var s = Settings.Current;
            if (s.AvWatchFolders.Count > 0) return s.AvWatchFolders.Where(Directory.Exists).ToList();
            string up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return new[]
            {
                Path.Combine(up, "Downloads"), Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), Path.GetTempPath().TrimEnd('\\'),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        static readonly HashSet<string> GuardExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".sys", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
          ".lnk", ".zip", ".jar", ".docm", ".xlsm", ".pptm", ".inf", ".php", ".aspx", ".iso", ".img" };

        void StartFileGuard()
        {
            foreach (string dir in WatchFolders())
            {
                try
                {
                    var w = new FileSystemWatcher(dir) { IncludeSubdirectories = true, InternalBufferSize = 64 * 1024, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size };
                    w.Created += (_, e) => Enqueue(e.FullPath);
                    w.Changed += (_, e) => Enqueue(e.FullPath);
                    w.Renamed += (_, e) => Enqueue(e.FullPath);
                    w.EnableRaisingEvents = true;
                    _watchers.Add(w);
                }
                catch (Exception ex) { Log.Debug("watch " + dir + ": " + ex.Message); }
            }
            _fileTimer = new Timer(_ => Safe(FileTick), null, 700, 700);
            Log.Add(EventKind.Antivirus, Severity.Info, "av.fileguard_on", $"File guard watching {_watchers.Count} folders", $"حارس الملفات يراقب {_watchers.Count} مجلدات", string.Join("\n", WatchFolders()));
        }

        void StopFileGuard()
        {
            foreach (var w in _watchers) { try { w.EnableRaisingEvents = false; w.Dispose(); } catch { } }
            _watchers.Clear(); _fileTimer?.Dispose(); _fileTimer = null; _queue.Clear();
        }

        void Enqueue(string path)
        {
            if (!GuardExt.Contains(Path.GetExtension(path))) return;
            if (Scanner.IsExcluded(path)) return;
            _queue[path] = DateTime.Now;
        }

        int _fileBusy;
        void FileTick()
        {
            if (Interlocked.Exchange(ref _fileBusy, 1) == 1) return;
            try
            {
                foreach (var kv in _queue.ToArray())
                {
                    if ((DateTime.Now - kv.Value).TotalMilliseconds < 600) continue;      // let the writer finish
                    _queue.TryRemove(kv.Key, out _);
                    if (!File.Exists(kv.Key)) continue;
                    var r = Scanner.Instance.ScanFile(kv.Key, false);
                    Interlocked.Increment(ref RealtimeScans);
                    if (r.Verdict == Verdict.Skipped && r.Error != null && r.Error.Contains("being used")) { _queue[kv.Key] = DateTime.Now; continue; }
                    if (r.Verdict == Verdict.Malicious || r.Verdict == Verdict.Suspicious) Handle(r, "file guard");
                }
            }
            finally { Interlocked.Exchange(ref _fileBusy, 0); }
        }

        // ------------------------------------------------------------------ process guard
        static readonly HashSet<string> Interpreters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe" };

        int _procBusy;
        void ProcessTick()
        {
            if (Interlocked.Exchange(ref _procBusy, 1) == 1) return;
            try
            {
                var now = new HashSet<int>();
                int self = Environment.ProcessId;
                foreach (var p in Process.GetProcesses())
                {
                    int pid = p.Id; p.Dispose();
                    now.Add(pid);
                    if (_knownPids.Contains(pid) || pid <= 4 || pid == self) continue;
                    if (!_procPrimed) continue;                      // first pass only records what is already running
                    string path = Fw.ConnMonitor.ProcessPath(pid);
                    if (string.IsNullOrEmpty(path) || !File.Exists(path)) continue;

                    string exe = Path.GetFileName(path);
                    if (Interpreters.Contains(exe))
                    {
                        string cl = Proc.CommandLine(pid);
                        if (!string.IsNullOrEmpty(cl))
                        {
                            // Editors, installers and admin tools routinely pass -EncodedCommand; decode it and judge the content.
                            string decoded = DecodeEncodedCommand(cl);
                            var hits = RuleEngine.Instance.Scan(Encoding.UTF8.GetBytes(cl + "\n" + decoded), "script", ".ps1", false, null)
                                .Where(h => h.Rule.id != "SOUR.PS.EncodedCommand").ToList();
                            var best = hits.OrderByDescending(h => h.Rule.score).FirstOrDefault();
                            if (best != null && best.Rule.score >= 60)
                            {
                                bool frozen = best.Rule.score >= 80 && Settings.Current.AvOnMalicious != AvAction.ReportOnly && Proc.Suspend(pid);
                                var r = new ScanResult { Path = path, Kind = "cmdline", Score = best.Rule.score, Verdict = best.Rule.score >= 80 ? Verdict.Malicious : Verdict.Suspicious };
                                r.Reasons.Add(new Reason(best.Rule.id, best.Rule.score, best.Rule.en + " — command line: " + Trim(cl), best.Rule.ar + " — سطر الأوامر: " + Trim(cl)));
                                var d = new Detection { Result = r, Source = "process guard", Pid = frozen ? pid : 0 };
                                Log.Add(EventKind.Antivirus, frozen ? Severity.Critical : Severity.High, "av.cmdline",
                                    $"Dangerous command line{(frozen ? " — process frozen" : "")}: {best.Rule.name}", $"سطر أوامر خطِر{(frozen ? " — جُمّدت العملية" : "")}: {best.Rule.name}", $"{exe} (pid {pid})\n{Trim(cl, 600)}", path);
                                lock (Pending) Pending.Add(d);
                                try { Detected?.Invoke(d); } catch { }
                            }
                        }
                        continue;
                    }
                    var res = Scanner.Instance.ScanFile(path);
                    Interlocked.Increment(ref RealtimeScans);
                    if (res.Verdict == Verdict.Malicious)
                    {
                        bool frozen = Settings.Current.AvOnMalicious != AvAction.ReportOnly && Proc.Suspend(pid);
                        Handle(res, "process guard", frozen ? pid : 0);
                    }
                    else if (res.Verdict == Verdict.Suspicious) Handle(res, "process guard");
                }
                _knownPids.Clear(); foreach (int pid in now) _knownPids.Add(pid);
                _procPrimed = true;
            }
            finally { Interlocked.Exchange(ref _procBusy, 0); }
        }

        /// <summary>Returns the script hidden in a PowerShell -EncodedCommand argument (Base64 of UTF-16LE), or "".</summary>
        public static string DecodeEncodedCommand(string commandLine)
        {
            try
            {
                var parts = commandLine.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i + 1 < parts.Length; i++)
                {
                    string p = parts[i].ToLowerInvariant();
                    if (p.Length < 2 || p[0] != '-' && p[0] != '/') continue;
                    string name = p.Substring(1);
                    if (name.Length == 0 || !"encodedcommand".StartsWith(name)) continue;       // -e, -ec, -enc, -encodedcommand
                    string b64 = parts[i + 1].Trim('"', '\'');
                    if (b64.Length < 8) continue;
                    return Encoding.Unicode.GetString(Convert.FromBase64String(b64));
                }
            }
            catch { }
            return "";
        }

        static string Trim(string s, int n = 180) => s.Length <= n ? s : s.Substring(0, n) + "…";

        // ------------------------------------------------------------------ ransomware shield
        readonly List<FileSystemWatcher> _ransomWatchers = new List<FileSystemWatcher>();
        readonly Queue<DateTime> _renames = new Queue<DateTime>();
        readonly Dictionary<int, ulong> _ioPrev = new Dictionary<int, ulong>();
        readonly Dictionary<int, ulong> _ioDelta = new Dictionary<int, ulong>();
        DateTime _lastRansomAlert = DateTime.MinValue;
        public const string CanaryPrefix = "!000_sour_guard_";

        public static List<string> ProtectedOverride;      // tests point the shield at scratch folders

        public static List<string> ProtectedFolders() => ProtectedOverride ?? new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
        }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        public static List<string> CanaryFiles() => ProtectedFolders().SelectMany(d => new[] { Path.Combine(d, CanaryPrefix + "a.docx"), Path.Combine(d, CanaryPrefix + "z.xlsx") }).ToList();

        void StartRansomShield()
        {
            foreach (string f in CanaryFiles())
            {
                try
                {
                    if (!File.Exists(f))
                    {
                        var rnd = new byte[2048]; Random.Shared.NextBytes(rnd);
                        File.WriteAllText(f, "Sour ransomware-shield decoy. Do not edit or delete.\r\n" + Convert.ToBase64String(rnd));
                        File.SetAttributes(f, FileAttributes.Hidden);
                    }
                }
                catch (Exception ex) { Log.Debug("canary " + f + ": " + ex.Message); }
            }
            foreach (string dir in ProtectedFolders())
            {
                try
                {
                    var w = new FileSystemWatcher(dir) { IncludeSubdirectories = true, InternalBufferSize = 64 * 1024, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size };
                    w.Changed += (_, e) => { if (IsCanary(e.FullPath)) RansomAlert("canary modified", "عُدِّل ملف الطُّعم", e.FullPath); };
                    w.Deleted += (_, e) => { if (IsCanary(e.FullPath)) RansomAlert("canary deleted", "حُذف ملف الطُّعم", e.FullPath); };
                    w.Renamed += (_, e) =>
                    {
                        if (IsCanary(e.OldFullPath)) { RansomAlert("canary renamed", "أُعيدت تسمية ملف الطُّعم", e.OldFullPath + " → " + e.Name); return; }
                        // mass renames that change the extension are the signature of file-encrypting malware
                        if (!string.Equals(Path.GetExtension(e.OldFullPath), Path.GetExtension(e.FullPath), StringComparison.OrdinalIgnoreCase))
                        {
                            lock (_renames)
                            {
                                _renames.Enqueue(DateTime.Now);
                                while (_renames.Count > 0 && (DateTime.Now - _renames.Peek()).TotalSeconds > 10) _renames.Dequeue();
                                if (_renames.Count >= 30) { _renames.Clear(); RansomAlert("30+ files changed extension within 10 s", "أكثر من 30 ملفاً تغيّر امتدادها خلال 10 ثوانٍ", dir); }
                            }
                        }
                    };
                    w.EnableRaisingEvents = true;
                    _ransomWatchers.Add(w);
                }
                catch (Exception ex) { Log.Debug("ransom watch " + dir + ": " + ex.Message); }
            }
            Log.Add(EventKind.Ransomware, Severity.Info, "rs.on", "Ransomware shield armed (decoy files placed)", "درع الفدية مفعّل (وُضعت ملفات الطُّعم)", string.Join("\n", CanaryFiles()));
        }

        void StopRansomShield()
        {
            if (_ransomWatchers.Count == 0) return;      // this instance never armed the shield: the decoys are not ours to remove
            foreach (var w in _ransomWatchers) { try { w.EnableRaisingEvents = false; w.Dispose(); } catch { } }
            _ransomWatchers.Clear();
            foreach (string f in CanaryFiles()) { try { if (File.Exists(f)) { File.SetAttributes(f, FileAttributes.Normal); File.Delete(f); } } catch { } }
        }

        static bool IsCanary(string path) => Path.GetFileName(path).StartsWith(CanaryPrefix, StringComparison.OrdinalIgnoreCase);

        void RansomAlert(string en, string ar, string evidence)
        {
            if ((DateTime.Now - _lastRansomAlert).TotalSeconds < 15) return;
            _lastRansomAlert = DateTime.Now;
            // suspect: the non-Microsoft process that wrote the most bytes in the last sampling window
            string suspectText = "no suspect identified";
            int suspectPid = 0; string suspectPath = null;
            try
            {
                Dictionary<int, ulong> delta; lock (_ioDelta) delta = new Dictionary<int, ulong>(_ioDelta);
                foreach (var kv in delta.OrderByDescending(k => k.Value).Take(8))
                {
                    if (kv.Value < 256 * 1024 || kv.Key == Environment.ProcessId) continue;
                    string path = Fw.ConnMonitor.ProcessPath(kv.Key);
                    if (!File.Exists(path)) continue;
                    if (string.Equals(Path.GetFileName(path), "Sour.exe", StringComparison.OrdinalIgnoreCase)) continue;
                    var t = Trust.Check(path);
                    if (t.Valid) continue;          // browsers, editors, sync clients write a lot and are signed: not suspects
                    suspectPid = kv.Key; suspectPath = path;
                    suspectText = $"{path} (pid {kv.Key}, wrote {Util.HumanSize((long)kv.Value)} in the last seconds, signer: {t.Describe()})";
                    break;
                }
            }
            catch { }
            bool frozen = suspectPid != 0 && Settings.Current.AvOnMalicious != AvAction.ReportOnly && Proc.Suspend(suspectPid);
            Log.Add(EventKind.Ransomware, Severity.Critical, "rs.alert", "Ransomware behaviour: " + en + (frozen ? " — suspect process frozen" : ""),
                "سلوك فدية: " + ar + (frozen ? " — جُمّدت العملية المشتبه بها" : ""), evidence + "\nsuspect: " + suspectText, suspectPath);
            if (suspectPath != null)
            {
                var r = new ScanResult { Path = suspectPath, Kind = "behaviour", Score = 90, Verdict = Verdict.Malicious };
                r.Reasons.Add(new Reason("Behaviour.Ransomware", 90, "Ransomware behaviour: " + en, "سلوك فدية: " + ar));
                var d = new Detection { Result = r, Source = "ransom shield", Pid = frozen ? suspectPid : 0 };
                lock (Pending) Pending.Add(d);
                try { Detected?.Invoke(d); } catch { }
            }
        }

        // ------------------------------------------------------------------ slow tick: IO sampling, USB, persistence
        HashSet<string> _drives; Dictionary<string, string> _autoruns; string _hostsHash; int _slowN;

        void SlowTick()
        {
            var s = Settings.Current;
            if (s.AvRansomShield)
            {
                var cur = new Dictionary<int, ulong>();
                foreach (var p in Process.GetProcesses()) { int pid = p.Id; p.Dispose(); if (pid > 4) cur[pid] = Proc.WriteBytes(pid); }
                lock (_ioDelta)
                {
                    _ioDelta.Clear();
                    foreach (var kv in cur) if (_ioPrev.TryGetValue(kv.Key, out ulong prev) && kv.Value > prev) _ioDelta[kv.Key] = kv.Value - prev;
                    _ioPrev.Clear(); foreach (var kv in cur) _ioPrev[kv.Key] = kv.Value;
                }
                // the decoys must still exist
                foreach (string f in CanaryFiles()) if (!File.Exists(f) && RansomShieldOn) { RansomAlert("canary missing", "ملف الطُّعم مفقود", f); break; }
            }

            if (s.AvUsbScan)
            {
                var now = new HashSet<string>(DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable && d.IsReady).Select(d => d.Name), StringComparer.OrdinalIgnoreCase);
                if (_drives != null) foreach (string d in now.Where(d => !_drives.Contains(d))) { string drive = d; ThreadPool.QueueUserWorkItem(_ => Safe(() => ScanUsb(drive))); }
                _drives = now;
            }

            if (s.AvPersistenceWatch && (_slowN++ % 5 == 0))
            {
                var cur = Autoruns();
                if (_autoruns != null)
                    foreach (var kv in cur.Where(kv => !_autoruns.ContainsKey(kv.Key) || _autoruns[kv.Key] != kv.Value))
                        NewAutorun(kv.Key, kv.Value);
                _autoruns = cur;
                try
                {
                    string hosts = Path.Combine(Environment.SystemDirectory, "drivers\\etc\\hosts");
                    string h = File.Exists(hosts) ? Util.Sha256(hosts) : "";
                    if (_hostsHash != null && h != _hostsHash)
                        Log.Add(EventKind.Persistence, Severity.High, "ps.hosts", "The hosts file was modified", "تم تعديل ملف hosts", hosts, hosts);
                    _hostsHash = h;
                }
                catch { }
            }
        }

        void ScanUsb(string drive)
        {
            Log.Add(EventKind.Antivirus, Severity.Info, "usb.inserted", $"Removable drive {drive} connected — scanning", $"وُصل قرص خارجي {drive} — يجري الفحص", drive);
            var opt = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 2 };
            int n = 0, bad = 0;
            foreach (string f in Directory.EnumerateFiles(drive, "*", opt))
            {
                if (!GuardExt.Contains(Path.GetExtension(f))) continue;
                if (++n > 3000) break;
                var r = Scanner.Instance.ScanFile(f);
                if (r.Verdict == Verdict.Malicious || r.Verdict == Verdict.Suspicious) { bad++; Handle(r, "usb"); }
            }
            Log.Add(EventKind.Antivirus, bad > 0 ? Severity.High : Severity.Info, "usb.done", $"Drive {drive}: {n} files checked, {bad} flagged", $"القرص {drive}: فُحص {n} ملفاً، {bad} مشبوهاً", drive);
        }

        public static Dictionary<string, string> Autoruns()
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            void Key(RegistryKey root, string name, string sub)
            {
                try
                {
                    using var k = root.OpenSubKey(sub);
                    if (k == null) return;
                    foreach (string v in k.GetValueNames()) d[$"{name}\\{sub}\\{v}"] = Convert.ToString(k.GetValue(v));
                }
                catch { }
            }
            foreach (string sub in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" })
            { Key(Registry.CurrentUser, "HKCU", sub); Key(Registry.LocalMachine, "HKLM", sub); }
            foreach (string dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
            {
                try { if (Directory.Exists(dir)) foreach (string f in Directory.GetFiles(dir)) if (!f.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)) d["Startup\\" + f] = File.GetLastWriteTimeUtc(f).Ticks.ToString(); } catch { }
            }
            return d;
        }

        /// <summary>Extracts the program path from a Run-key command line.</summary>
        public static string CommandTarget(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return null;
            cmd = Environment.ExpandEnvironmentVariables(cmd.Trim());
            if (cmd.StartsWith("\"")) { int e = cmd.IndexOf('"', 1); return e > 1 ? cmd.Substring(1, e - 1) : null; }
            int i = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return i > 0 ? cmd.Substring(0, i + 4) : cmd.Split(' ')[0];
        }

        void NewAutorun(string where, string value)
        {
            string target = where.StartsWith("Startup\\") ? where.Substring(8) : CommandTarget(value);
            ScanResult r = null;
            if (target != null && File.Exists(target)) r = Scanner.Instance.ScanFile(target);
            var sev = r != null && r.Verdict == Verdict.Malicious ? Severity.Critical : r != null && r.Verdict == Verdict.Suspicious ? Severity.High : Severity.Medium;
            Log.Add(EventKind.Persistence, sev, "ps.autorun", "New program registered to start with Windows", "برنامج جديد سُجّل ليعمل مع بدء ويندوز",
                $"{where}\n{value}\n{(r == null ? "target not found" : $"scan: {r.Verdict} ({r.Score}) signer: {r.Signer}")}", target);
            if (r != null && (r.Verdict == Verdict.Malicious || r.Verdict == Verdict.Suspicious)) Handle(r, "startup");
        }
    }
}
