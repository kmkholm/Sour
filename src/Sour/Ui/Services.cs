using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Sour.Av;
using Sour.Core;
using Sour.Fw;

namespace Sour.Ui
{
    /// <summary>Background wiring: connection monitor → network AI, guards, block watcher, periodic integrity checks.</summary>
    public static class Services
    {
        public static readonly ConnMonitor Conn = new ConnMonitor();
        public static readonly NetAnomaly NetAi = new NetAnomaly();
        public static readonly ConcurrentDictionary<string, int> SeenApps = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public static long NetAlerts;
        static Timer _housekeeping;
        static bool _started;

        public static void Start()
        {
            if (_started) return; _started = true;
            Log.LoadFromDisk();
            Conn.NewConnection += OnConnection;
            Conn.Start();
            Guard.Instance.Sync();
            SyncBlockWatcher();
            _housekeeping = new Timer(_ => { try { Housekeeping(); } catch { } }, null, 60_000, 300_000);
            Log.Add(EventKind.System, Severity.Info, "sys.start", "Sour started" + (Util.IsAdmin() ? " (administrator)" : " (standard user)"), "بدأ سور" + (Util.IsAdmin() ? " (بصلاحية مدير)" : " (مستخدم عادي)"));
        }

        public static void Stop()
        {
            try { NetAi.Save(); } catch { }
            Conn.Stop(); Guard.Instance.StopAll(); BlockWatcher.Instance.Stop(); _housekeeping?.Dispose();
        }

        public static void SyncBlockWatcher()
        {
            var s = Settings.Current;
            bool want = Util.IsAdmin() && s.FwAuditEvents && s.FirewallMode != FwMode.Off && s.FirewallMode != FwMode.Monitor;
            if (want) BlockWatcher.Instance.Start(); else BlockWatcher.Instance.Stop();
        }

        static void OnConnection(Conn c)
        {
            if (string.IsNullOrEmpty(c.ProcessPath)) return;
            SeenApps.AddOrUpdate(c.ProcessPath, 1, (_, n) => n + 1);
            if (!Settings.Current.NetAi || c.Remote == null) return;
            bool risky = false;
            try
            {
                if (File.Exists(c.ProcessPath))
                {
                    string up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    bool userDir = c.ProcessPath.StartsWith(up, StringComparison.OrdinalIgnoreCase) || c.ProcessPath.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase);
                    risky = userDir && !Trust.Check(c.ProcessPath).Valid;
                }
            }
            catch { }
            var v = NetAi.Observe(c, DateTime.Now, risky);
            c.Risk = v.Score; c.RiskWhy = v.Why;
            if (v.Score >= Settings.Current.NetAiAlertScore)
            {
                Interlocked.Increment(ref NetAlerts);
                Log.Add(EventKind.Network, v.Score >= 85 ? Severity.High : Severity.Medium, "net.anomaly",
                    $"Unusual connection by {c.ProcessName} (risk {v.Score:0})", $"اتصال غير معتاد من {c.ProcessName} (خطورة {v.Score:0})",
                    $"{c.ProcessPath}\n→ {(string.IsNullOrEmpty(c.Host) ? "" : c.Host + " ")}{c.Remote}:{c.RemotePort}\n{v.Why}", c.ProcessPath);
            }
        }

        static void Housekeeping()
        {
            var s = Settings.Current;
            try { ScheduledScan(); } catch { }
            try
            {
                foreach (var d in Extras.LanDevices().Where(d => d.IsNew))
                    Log.Add(EventKind.Network, Severity.Medium, "lan.new_device", $"New device on the network: {d.Ip}", $"جهاز جديد على الشبكة: {d.Ip}", $"{d.Ip}  {d.Mac}");
            }
            catch { }
            bool reapply = FirewallEngine.PruneExpired() > 0;
            if (s.FwHashPinning && FirewallEngine.VerifyPins().Count > 0) reapply = true;
            if (reapply && Util.IsAdmin() && s.FirewallMode != FwMode.Off) FirewallEngine.Apply();
            NetAi.Save();
            // tamper check: are our filters still in the engine?
            if (Util.IsAdmin() && (s.FirewallMode == FwMode.Whitelist || s.FirewallMode == FwMode.Blocklist || s.FirewallMode == FwMode.Lockdown))
            {
                var live = FirewallEngine.LiveState();
                if (live.ok && live.count == 0 && RuleStore.Current.ActiveFilterIds.Count > 0)
                {
                    Log.Add(EventKind.Firewall, Severity.Critical, "fw.tamper", "Firewall filters were removed by another program — restoring", "أُزيلت مرشّحات الجدار الناري من برنامج آخر — تجري إعادتها");
                    FirewallEngine.Apply();
                }
            }
        }

        /// <summary>0..100 summary of how many protection layers are active.</summary>
        public static (int score, List<(string name, bool on, int weight)> parts) ProtectionScore()
        {
            var s = Settings.Current; var g = Guard.Instance;
            bool fw = s.FirewallMode == FwMode.Whitelist || s.FirewallMode == FwMode.Blocklist || s.FirewallMode == FwMode.Lockdown;
            var parts = new List<(string, bool, int)>
            {
                (I18n.T("Firewall enforcing", "الجدار الناري يفرض السياسة"), fw, 25),
                (I18n.T("Default-deny (whitelist)", "المنع الافتراضي (قائمة بيضاء)"), s.FirewallMode == FwMode.Whitelist || s.FirewallMode == FwMode.Lockdown, 10),
                (I18n.T("File guard", "حارس الملفات"), g.FileGuardOn, 15),
                (I18n.T("Process guard", "حارس العمليات"), g.ProcessGuardOn, 15),
                (I18n.T("Ransomware shield", "درع الفدية"), g.RansomShieldOn, 15),
                (I18n.T("AI model loaded", "نموذج الذكاء الاصطناعي محمَّل"), MlModel.Instance.Loaded && s.AvUseMl, 10),
                (I18n.T("Network AI", "ذكاء الشبكة"), s.NetAi, 5),
                (I18n.T("Startup + USB watch", "مراقبة بدء التشغيل و USB"), s.AvPersistenceWatch && s.AvUsbScan, 5),
            };
            return (parts.Where(p => p.Item2).Sum(p => p.Item3), parts);
        }

        // ---------------- threat feeds (only when the user presses the button)
        public const string IpFeedUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";

        public static async Task<string> UpdateFeeds()
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(40) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("Sour/1.0");
            int ips = 0; var notes = new List<string>();
            try
            {
                string txt = await http.GetStringAsync(IpFeedUrl);
                var store = RuleStore.Current;
                store.BlockedIps.RemoveAll(i => i.Note == "feed:feodo");
                foreach (string l in txt.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 6 && l[0] != '#'))
                    if (FirewallEngine.TryParseCidr(l, out _, out _) && ips < 2000) { store.BlockedIps.Add(new IpRule { Cidr = l, Note = "feed:feodo" }); ips++; }
                RuleStore.Save();
            }
            catch (Exception ex) { notes.Add("ip feed: " + ex.Message); }
            Log.Add(EventKind.System, Severity.Info, "feeds.updated", $"Threat feed updated: {ips} botnet C2 addresses", $"حُدّثت قائمة التهديدات: {ips} عنوان خادم تحكّم", string.Join("\n", notes));
            return I18n.T($"{ips} botnet C2 addresses in the block list (apply the firewall policy to enforce them)", $"{ips} عنوان خادم تحكّم في قائمة الحظر (طبّق سياسة الجدار لفرضها)") + (notes.Count > 0 ? "\n" + string.Join("\n", notes) : "");
        }

        /// <summary>Imports SHA-256 values (one per line, anything after the hash is ignored) into the feed block list.</summary>
        public static int ImportHashes(string file)
        {
            var lines = File.ReadLines(file).Select(l => l.Trim()).Where(l => l.Length >= 64 && l.Substring(0, 64).All(Uri.IsHexDigit)).Select(l => l.Substring(0, 64).ToLowerInvariant()).Distinct().ToList();
            if (lines.Count == 0) return 0;
            File.AppendAllLines(HashDb.FeedFile, lines); HashDb.Reload();
            return lines.Count;
        }

        // ---------------- Explorer right-click entry (per user, no administrator rights needed)
        public static void SetExplorerMenu(bool on)
        {
            foreach (string root in new[] { @"Software\Classes\*\shell\SourScan", @"Software\Classes\Directory\shell\SourScan" })
            {
                if (!on) { try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(root, false); } catch { } continue; }
                using var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(root);
                k.SetValue("", I18n.T("Scan with Sour", "فحص بواسطة سور"));
                k.SetValue("Icon", Environment.ProcessPath);
                using var c = k.CreateSubKey("command");
                c.SetValue("", $"\"{Environment.ProcessPath}\" --scan-ui \"%1\"");
            }
        }

        static int _scheduledBusy;
        static void ScheduledScan()
        {
            var s = Settings.Current;
            string today = DateTime.Now.ToString("yyyy-MM-dd");
            if (s.ScheduledScanHour < 0 || DateTime.Now.Hour != s.ScheduledScanHour || s.LastScheduledScan == today) return;
            if (Interlocked.Exchange(ref _scheduledBusy, 1) == 1) return;
            try
            {
                s.LastScheduledScan = today; Settings.Save();
                var found = Scanner.Instance.ScanPaths(Scanner.QuickScanRoots(), false, null, CancellationToken.None);
                foreach (var r in found) Guard.Instance.Handle(r, "scan");
                Log.Add(EventKind.Antivirus, found.Count > 0 ? Severity.Medium : Severity.Info, "av.scheduled", $"Scheduled quick scan finished: {found.Count} flagged", $"انتهى الفحص المجدول: {found.Count} مشبوهاً");
            }
            finally { Interlocked.Exchange(ref _scheduledBusy, 0); }
        }

        // ---------------- start with Windows (scheduled task, highest privileges so the firewall can be managed)
        const string TaskName = "Sour Firewall";
        public static bool AutoStartEnabled() => Util.Run("schtasks.exe", $"/query /tn \"{TaskName}\"").code == 0;
        public static bool SetAutoStart(bool on)
        {
            if (!on) return Util.Run("schtasks.exe", $"/delete /tn \"{TaskName}\" /f").code == 0;
            string exe = Environment.ProcessPath;
            return Util.Run("schtasks.exe", $"/create /tn \"{TaskName}\" /tr \"\\\"{exe}\\\" --minimized\" /sc onlogon /rl highest /f").code == 0;
        }
    }
}
