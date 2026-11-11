using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Microsoft.Win32;
using Sour.Core;
using Sour.Fw;

namespace Sour.Av
{
    public enum AuditState { Good, Bad, Unknown }

    public sealed class AuditItem
    {
        public string Id; public AuditState State; public int Weight;
        public string En, Ar;            // what was checked
        public string FoundEn, FoundAr;  // what was found
        public string FixEn, FixAr;      // what to do about it (empty when good)
        public string Title => I18n.T(En, Ar);
        public string Found => I18n.T(FoundEn, FoundAr);
        public string Fix => I18n.T(FixEn, FixAr);
    }

    public sealed class StartupEntry
    {
        public string Where, Command, Target, Signer; public Verdict Verdict; public int Score; public bool Missing;
    }

    /// <summary>
    /// Read-only security posture audit. It only reads settings (registry, netsh, the port table); it changes nothing.
    /// The checks follow the common ground of the CIS Windows 11 benchmark and the ACSC workstation hardening guide.
    /// </summary>
    public static class Audit
    {
        static object Reg(RegistryKey root, string key, string value)
        {
            try { using var k = root.OpenSubKey(key); return k?.GetValue(value); } catch { return null; }
        }
        static int? Int(object o) { try { return o == null ? (int?)null : Convert.ToInt32(o); } catch { return null; } }

        static AuditItem Item(string id, int weight, string en, string ar, AuditState st, string fen, string far, string fixEn = "", string fixAr = "")
            => new AuditItem { Id = id, Weight = weight, En = en, Ar = ar, State = st, FoundEn = fen, FoundAr = far, FixEn = st == AuditState.Good ? "" : fixEn, FixAr = st == AuditState.Good ? "" : fixAr };

        static AuditState Is(bool? ok) => ok == null ? AuditState.Unknown : ok.Value ? AuditState.Good : AuditState.Bad;

        public static List<AuditItem> Run()
        {
            var list = new List<AuditItem>();
            var lm = Registry.LocalMachine; var cu = Registry.CurrentUser;
            void Try(Action a) { try { a(); } catch { } }

            Try(() =>
            {
                int? lua = Int(Reg(lm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"));
                int? prompt = Int(Reg(lm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin"));
                bool? ok = lua == null ? (bool?)null : lua == 1 && prompt != 0;
                list.Add(Item("uac", 10, "User Account Control (UAC)", "التحكم بحساب المستخدم (UAC)", Is(ok),
                    lua == 1 ? (prompt == 0 ? "on, but administrators are elevated without a prompt" : "on, administrators are prompted") : "off",
                    lua == 1 ? (prompt == 0 ? "مفعّل لكن يُرفع المدير دون سؤال" : "مفعّل ويُسأل المدير") : "معطّل",
                    "Turn UAC on with a consent prompt: programs should not get administrator rights silently.", "فعّل UAC مع طلب الموافقة: لا ينبغي أن تحصل البرامج على صلاحية المدير بصمت."));
            });
            Try(() =>
            {
                int? off = Int(Reg(lm, @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"));
                int? pol = Int(Reg(lm, @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"));
                bool bad = off == 1 || pol == 1;
                list.Add(Item("defender", 10, "Microsoft Defender real-time protection", "الحماية الفورية في Microsoft Defender", bad ? AuditState.Bad : AuditState.Good,
                    bad ? "switched off" : "not switched off by registry or policy", bad ? "معطّلة" : "غير معطّلة من السجل أو السياسات",
                    "Turn real-time protection back on in Windows Security. Sour works beside Defender, not instead of it.", "أعد تفعيل الحماية الفورية من «أمن Windows». سور يعمل بجانب Defender لا بديلاً عنه."));
            });
            Try(() =>
            {
                int? tp = Int(Reg(lm, @"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection"));
                list.Add(Item("tamper", 6, "Defender tamper protection", "حماية Defender من العبث", tp == null ? AuditState.Unknown : Is(tp == 5),
                    tp == null ? "could not be read" : tp == 5 ? "on" : "off (value " + tp + ")", tp == null ? "تعذّرت القراءة" : tp == 5 ? "مفعّلة" : "معطّلة (القيمة " + tp + ")",
                    "Enable Tamper Protection in Windows Security → Virus & threat protection settings.", "فعّل «الحماية من العبث» من أمن Windows ← إعدادات الحماية من الفيروسات."));
            });
            Try(() =>
            {
                var offProfiles = new List<string>();
                foreach (var (key, name) in new[] { ("DomainProfile", "Domain"), ("StandardProfile", "Private"), ("PublicProfile", "Public") })
                    if (Int(Reg(lm, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + key, "EnableFirewall")) == 0) offProfiles.Add(name);
                list.Add(Item("winfw", 8, "Windows Firewall profiles", "ملفات تعريف جدار Windows", Is(offProfiles.Count == 0),
                    offProfiles.Count == 0 ? "all three profiles are on" : "off for: " + string.Join(", ", offProfiles), offProfiles.Count == 0 ? "الثلاثة مفعّلة" : "معطّل في: " + string.Join("، ", offProfiles),
                    "Turn Windows Firewall on for every profile; Sour's filters add to it.", "فعّل جدار Windows في كل الملفات؛ مرشّحات سور تُضاف إليه."));
            });
            Try(() =>
            {
                int? smb1 = Int(Reg(lm, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"));
                list.Add(Item("smb1", 8, "SMBv1 file sharing (WannaCry / NotPetya path)", "مشاركة الملفات SMBv1 (مسار WannaCry و NotPetya)", Is(smb1 != 1),
                    smb1 == 1 ? "enabled" : "not enabled", smb1 == 1 ? "مفعّل" : "غير مفعّل",
                    "Disable SMBv1: Turn Windows features on or off → untick “SMB 1.0/CIFS File Sharing Support”.", "عطّل SMBv1 من «تشغيل ميزات Windows أو إيقافها» ← أزل علامة «دعم مشاركة ملفات SMB 1.0/CIFS»."));
            });
            Try(() =>
            {
                int? deny = Int(Reg(lm, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"));
                int? nla = Int(Reg(lm, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication"));
                bool rdpOn = deny == 0;
                list.Add(Item("rdp", 8, "Remote Desktop", "سطح المكتب البعيد", Is(!rdpOn || nla == 1),
                    !rdpOn ? "off" : nla == 1 ? "on, with Network Level Authentication" : "on WITHOUT Network Level Authentication",
                    !rdpOn ? "معطّل" : nla == 1 ? "مفعّل مع مصادقة مستوى الشبكة" : "مفعّل دون مصادقة مستوى الشبكة",
                    "Require Network Level Authentication, or switch Remote Desktop off if you do not use it.", "افرض مصادقة مستوى الشبكة، أو عطّل سطح المكتب البعيد إن لم تستخدمه."));
            });
            Try(() =>
            {
                int? ppl = Int(Reg(lm, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"));
                list.Add(Item("lsa", 6, "LSA protection (blocks password dumping from memory)", "حماية LSA (تمنع سحب كلمات المرور من الذاكرة)", Is(ppl >= 1),
                    ppl >= 1 ? "on" : "off", ppl >= 1 ? "مفعّلة" : "معطّلة",
                    "Windows Security → Device security → Core isolation → Local Security Authority protection.", "أمن Windows ← أمان الجهاز ← عزل النواة ← حماية سلطة الأمان المحلية."));
            });
            Try(() =>
            {
                int? hvci = Int(Reg(lm, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled"));
                list.Add(Item("hvci", 5, "Memory integrity (core isolation)", "تكامل الذاكرة (عزل النواة)", Is(hvci == 1),
                    hvci == 1 ? "on" : "off", hvci == 1 ? "مفعّل" : "معطّل",
                    "Windows Security → Device security → Core isolation → Memory integrity. Some old drivers prevent it.", "أمن Windows ← أمان الجهاز ← عزل النواة ← تكامل الذاكرة. بعض التعريفات القديمة تمنعه."));
            });
            Try(() =>
            {
                int? sb = Int(Reg(lm, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"));
                list.Add(Item("secureboot", 6, "Secure Boot", "الإقلاع الآمن", sb == null ? AuditState.Unknown : Is(sb == 1),
                    sb == null ? "could not be read" : sb == 1 ? "on" : "off", sb == null ? "تعذّرت القراءة" : sb == 1 ? "مفعّل" : "معطّل",
                    "Enable Secure Boot in the UEFI firmware settings; it stops boot-level malware.", "فعّل الإقلاع الآمن من إعدادات UEFI؛ يمنع برمجيات مرحلة الإقلاع."));
            });
            Try(() =>
            {
                string auto = Convert.ToString(Reg(lm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon"));
                bool pw = Reg(lm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword") != null;
                bool bad = auto == "1" || pw;
                list.Add(Item("autologon", 7, "Automatic sign-in", "تسجيل الدخول التلقائي", Is(!bad),
                    bad ? (pw ? "on, and a password is stored in the registry in clear text" : "on") : "off", bad ? (pw ? "مفعّل وكلمة المرور مخزّنة في السجل بنص صريح" : "مفعّل") : "معطّل",
                    "Turn automatic sign-in off (netplwiz) and remove the stored password.", "عطّل الدخول التلقائي (netplwiz) واحذف كلمة المرور المخزّنة."));
            });
            Try(() =>
            {
                int? hide = Int(Reg(cu, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt"));
                list.Add(Item("ext", 4, "File extensions shown in Explorer", "إظهار امتدادات الملفات في المستكشف", Is(hide == 0),
                    hide == 0 ? "shown" : "hidden — “invoice.pdf.exe” looks like “invoice.pdf”", hide == 0 ? "ظاهرة" : "مخفية — يظهر «invoice.pdf.exe» كأنه «invoice.pdf»",
                    "Explorer → View → Show → File name extensions.", "المستكشف ← عرض ← إظهار ← ملحقات أسماء الملفات."));
            });
            Try(() =>
            {
                int? ra = Int(Reg(lm, @"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp"));
                list.Add(Item("remoteassist", 3, "Remote Assistance invitations", "دعوات المساعدة عن بعد", Is(ra != 1),
                    ra == 1 ? "allowed" : "not allowed", ra == 1 ? "مسموحة" : "غير مسموحة",
                    "System Properties → Remote → untick “Allow Remote Assistance connections”.", "خصائص النظام ← عن بعد ← أزل «السماح باتصالات المساعدة عن بعد»."));
            });
            Try(() =>
            {
                int? mc = Int(Reg(lm, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"));
                list.Add(Item("llmnr", 3, "LLMNR name resolution (credential-relay risk on shared networks)", "تحليل الأسماء LLMNR (خطر ترحيل بيانات الدخول على الشبكات المشتركة)", Is(mc == 0),
                    mc == 0 ? "disabled by policy" : "enabled (Windows default)", mc == 0 ? "معطّل بالسياسة" : "مفعّل (الوضع الافتراضي)",
                    "Group Policy → Network → DNS Client → Turn off multicast name resolution.", "نهج المجموعة ← الشبكة ← عميل DNS ← إيقاف تحليل الأسماء متعدد الإرسال."));
            });
            Try(() =>
            {
                var (code, outp) = Util.Run("netsh.exe", "wlan show interfaces", 8000);
                string auth = null, ssid = null;
                foreach (string line in outp.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase)) auth = t.Substring(t.IndexOf(':') + 1).Trim();
                    else if (t.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) && ssid == null) ssid = t.Substring(t.IndexOf(':') + 1).Trim();
                }
                if (auth == null)
                    list.Add(Item("wifi", 6, "Wi-Fi encryption", "تشفير شبكة Wi-Fi", AuditState.Unknown, "not connected to Wi-Fi (or not readable)", "غير متصل بـ Wi-Fi (أو تعذّرت القراءة)"));
                else
                {
                    bool weak = auth.Contains("Open", StringComparison.OrdinalIgnoreCase) || auth.Contains("WEP", StringComparison.OrdinalIgnoreCase) || auth.Equals("WPA-Personal", StringComparison.OrdinalIgnoreCase);
                    list.Add(Item("wifi", 6, "Wi-Fi encryption", "تشفير شبكة Wi-Fi", Is(!weak), $"{ssid}: {auth}", $"{ssid}: {auth}",
                        "This network is open or uses broken encryption: anyone nearby can read or alter traffic. Prefer WPA2/WPA3, or use a VPN on it.", "هذه الشبكة مفتوحة أو تشفيرها مكسور: من حولك يستطيع قراءة المرور أو تعديله. استخدم WPA2/WPA3 أو VPN."));
                }
            });
            Try(() =>
            {
                var risky = new Dictionary<int, string> { [445] = "SMB", [3389] = "RDP", [135] = "RPC", [139] = "NetBIOS", [5900] = "VNC", [23] = "Telnet", [21] = "FTP", [5985] = "WinRM", [22] = "SSH" };
                var open = ConnMonitor.Snapshot().Where(c => c.IsListener && c.Protocol == "TCP" && c.Local != null && (c.Local.Equals(IPAddress.Any) || c.Local.Equals(IPAddress.IPv6Any)) && risky.ContainsKey(c.LocalPort))
                    .Select(c => $"{c.LocalPort} {risky[c.LocalPort]} ({c.ProcessName})").Distinct().ToList();
                bool stealth = Settings.Current.FwBlockInbound && Settings.Current.FirewallMode >= FwMode.Blocklist;
                list.Add(Item("ports", 7, "Remote-access services listening on all networks", "خدمات وصول بعيد تنصت على كل الشبكات", Is(open.Count == 0),
                    open.Count == 0 ? "none" : string.Join(", ", open) + (stealth ? " — covered by Sour stealth inbound" : ""), open.Count == 0 ? "لا شيء" : string.Join("، ", open) + (stealth ? " — يغطيها تخفّي سور" : ""),
                    "Stop services you do not use, or enable Sour's stealth inbound so only allowed programs can be reached.", "أوقف الخدمات التي لا تستخدمها، أو فعّل التخفّي في سور كي لا يُوصَل إلا للبرامج المسموح لها."));
            });
            Try(() =>
            {
                string hosts = Path.Combine(Environment.SystemDirectory, "drivers\\etc\\hosts");
                var entries = File.Exists(hosts) ? File.ReadAllLines(hosts).Select(l => l.Trim()).Where(l => l.Length > 0 && l[0] != '#').ToList() : new List<string>();
                var redirects = entries.Where(l =>
                {
                    // only a name pointed at a PUBLIC address is a redirection worth flagging (Docker/VM entries point at private ones)
                    string first = l.Split(new[] { ' ', '	' }, StringSplitOptions.RemoveEmptyEntries)[0];
                    if (!IPAddress.TryParse(first, out var ip) || first.StartsWith("0.") || NetAnomaly.IsPrivate(ip)) return false;
                    var ipb = ip.GetAddressBytes();
                    return !(ipb.Length == 4 && ipb[0] == 100 && ipb[1] >= 64 && ipb[1] <= 127);      // 100.64/10: carrier-grade NAT, used by mesh VPNs
                }).ToList();
                list.Add(Item("hosts", 4, "hosts file redirections", "تحويلات ملف hosts", Is(redirects.Count == 0),
                    redirects.Count == 0 ? $"{entries.Count} entries, none redirects a name to another server" : $"{redirects.Count} names are redirected, e.g. {redirects[0]}",
                    redirects.Count == 0 ? $"{entries.Count} مدخلاً، لا يحوّل أيٌّ منها اسماً إلى خادم آخر" : $"{redirects.Count} اسماً محوَّلاً، مثل {redirects[0]}",
                    "Review the hosts file: malware redirects bank or update sites this way.", "راجع ملف hosts: البرمجيات الخبيثة تحوّل مواقع البنوك والتحديثات بهذه الطريقة."));
            });
            Try(() =>
            {
                var s = Settings.Current; var g = Guard.Instance;
                bool fw = s.FirewallMode >= FwMode.Blocklist;
                list.Add(Item("sour.fw", 6, "Sour firewall enforcing", "جدار سور يفرض السياسة", Is(fw), fw ? "mode: " + s.FirewallMode : "mode: " + s.FirewallMode + " (nothing is blocked)", fw ? "الوضع: " + FirewallEngine.ModeAr(s.FirewallMode) : "الوضع: " + FirewallEngine.ModeAr(s.FirewallMode) + " (لا يُحجب شيء)",
                    "Choose Block list or Whitelist on the Firewall page and apply.", "اختر «قائمة الحظر» أو «القائمة البيضاء» من صفحة الجدار الناري وطبّق."));
                bool live = g.FileGuardOn && g.ProcessGuardOn && g.RansomShieldOn;
                list.Add(Item("sour.live", 6, "Sour live protection", "الحماية الحيّة في سور", Is(live), live ? "file guard, process guard and ransomware shield are on" : "not all three guards are on", live ? "حارس الملفات وحارس العمليات ودرع الفدية تعمل" : "ليست الحراسات الثلاث كلها تعمل",
                    "Turn the guards on from the overview page.", "شغّل الحراسات من صفحة النظرة العامة."));
            });
            return list;
        }

        /// <summary>Share of the weighted checks that passed; checks that could not be read are left out.</summary>
        public static int Score(List<AuditItem> items)
        {
            int total = items.Where(i => i.State != AuditState.Unknown).Sum(i => i.Weight);
            return total == 0 ? 0 : (int)Math.Round(100.0 * items.Where(i => i.State == AuditState.Good).Sum(i => i.Weight) / total);
        }

        /// <summary>Everything registered to start with Windows, each checked for signature and scanned.</summary>
        public static List<StartupEntry> Startup()
        {
            var res = new List<StartupEntry>();
            foreach (var kv in Guard.Autoruns())
            {
                bool folder = kv.Key.StartsWith("Startup\\");
                var e = new StartupEntry { Where = folder ? "Startup folder" : kv.Key.Substring(0, kv.Key.LastIndexOf('\\')), Command = folder ? kv.Key.Substring(8) : kv.Value };
                e.Target = folder ? kv.Key.Substring(8) : Guard.CommandTarget(kv.Value);
                if (e.Target != null && File.Exists(e.Target))
                {
                    var r = Scanner.Instance.ScanFile(e.Target);
                    e.Verdict = r.Verdict; e.Score = r.Score;
                    e.Signer = r.Signer ?? (e.Target.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? "shortcut" : "");
                }
                else e.Missing = true;
                res.Add(e);
            }
            return res.OrderByDescending(x => x.Score).ThenBy(x => x.Where).ToList();
        }

        /// <summary>Scans the image file of every running process (each distinct file once).</summary>
        public static List<ScanResult> ScanRunning(Action<int, int> progress = null)
        {
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in System.Diagnostics.Process.GetProcesses())
            {
                int pid = p.Id; p.Dispose();
                if (pid <= 4) continue;
                string path = ConnMonitor.ProcessPath(pid);
                if (!string.IsNullOrEmpty(path) && File.Exists(path)) paths.Add(path);
            }
            var found = new List<ScanResult>(); int n = 0;
            foreach (string path in paths)
            {
                var r = Scanner.Instance.ScanFile(path);
                if (r.Verdict == Verdict.Malicious || r.Verdict == Verdict.Suspicious) found.Add(r);
                progress?.Invoke(++n, paths.Count);
            }
            return found;
        }

        // ---------------- HTML report
        static string H(string s) => WebUtility.HtmlEncode(s ?? "");

        public static string HtmlReport(List<AuditItem> items, List<StartupEntry> startup, List<ScanResult> findings)
        {
            bool ar = I18n.IsArabic;
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"").Append(ar ? "ar" : "en").Append("\" dir=\"").Append(ar ? "rtl" : "ltr").Append("\"><meta charset=\"utf-8\"><title>Sour report</title>");
            sb.Append("<style>body{font-family:'Segoe UI',Tahoma,sans-serif;background:#ece6da;color:#111317;margin:32px;max-width:1000px}h1{font-size:30px;margin:0}h2{font-size:17px;border-bottom:2px solid #111317;padding-bottom:4px;margin-top:30px}table{border-collapse:collapse;width:100%;background:#fbf8f1}td,th{border-bottom:1px solid #c9c1b1;padding:7px 10px;text-align:start;vertical-align:top;font-size:13.5px}th{background:#111317;color:#fff;font-weight:600}.g{color:#1e7a46;font-weight:700}.b{color:#b3261e;font-weight:700}.u{color:#5e6672}code{font-family:Consolas,monospace;font-size:12px;direction:ltr;unicode-bidi:embed}.m{color:#5e6672;font-size:12.5px}</style>");
            sb.Append("<h1>").Append(I18n.T("Sour security report", "تقرير سور الأمني")).Append("</h1><p class=m>")
              .Append(H(Environment.MachineName)).Append(" · ").Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm")).Append(" · ")
              .Append(I18n.T("hardening score ", "درجة الصلابة ")).Append(Score(items)).Append("/100</p>");

            sb.Append("<h2>").Append(I18n.T("System hardening", "صلابة النظام")).Append("</h2><table><tr><th>").Append(I18n.T("Check", "الفحص")).Append("</th><th>").Append(I18n.T("Found", "النتيجة")).Append("</th><th>").Append(I18n.T("What to do", "ما العمل")).Append("</th></tr>");
            foreach (var i in items.OrderBy(i => i.State == AuditState.Bad ? 0 : i.State == AuditState.Unknown ? 1 : 2))
                sb.Append("<tr><td>").Append(H(i.Title)).Append("</td><td class=").Append(i.State == AuditState.Good ? "g" : i.State == AuditState.Bad ? "b" : "u").Append(">").Append(H(i.Found)).Append("</td><td>").Append(H(i.Fix)).Append("</td></tr>");
            sb.Append("</table>");

            if (startup != null)
            {
                sb.Append("<h2>").Append(I18n.T("Programs that start with Windows", "برامج تعمل مع بدء Windows")).Append(" (").Append(startup.Count).Append(")</h2><table><tr><th>").Append(I18n.T("Where", "الموضع")).Append("</th><th>").Append(I18n.T("Program", "البرنامج")).Append("</th><th>").Append(I18n.T("Signer", "الموقِّع")).Append("</th><th>").Append(I18n.T("Verdict", "الحكم")).Append("</th></tr>");
                foreach (var e in startup)
                    sb.Append("<tr><td><code>").Append(H(e.Where)).Append("</code></td><td><code>").Append(H(e.Target ?? e.Command)).Append("</code></td><td>").Append(H(e.Missing ? I18n.T("file not found", "الملف غير موجود") : e.Signer)).Append("</td><td class=").Append(e.Verdict == Verdict.Clean ? "g" : "b").Append(">").Append(e.Missing ? "—" : e.Verdict + " " + e.Score).Append("</td></tr>");
                sb.Append("</table>");
            }
            if (findings != null && findings.Count > 0)
            {
                sb.Append("<h2>").Append(I18n.T("Flagged files", "ملفات مرصودة")).Append(" (").Append(findings.Count).Append(")</h2><table><tr><th>").Append(I18n.T("File", "الملف")).Append("</th><th>").Append(I18n.T("Verdict", "الحكم")).Append("</th><th>").Append(I18n.T("Why", "السبب")).Append("</th></tr>");
                foreach (var r in findings.OrderByDescending(r => r.Score))
                    sb.Append("<tr><td><code>").Append(H(r.Path)).Append("</code></td><td class=b>").Append(r.Verdict).Append(' ').Append(r.Score).Append("</td><td>").Append(H(string.Join(" · ", r.Reasons.OrderByDescending(x => x.Weight).Take(4).Select(x => x.Text)))).Append("</td></tr>");
                sb.Append("</table>");
            }
            sb.Append("<p class=m>").Append(I18n.T("Generated locally by Sour. The audit only reads settings; it changes nothing.", "أُنشئ محلياً بواسطة سور. التدقيق يقرأ الإعدادات فقط ولا يغيّر شيئاً.")).Append("</p></html>");
            return sb.ToString();
        }
    }
}
