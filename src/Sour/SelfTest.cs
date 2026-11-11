using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using Sour.Av;
using Sour.Core;
using Sour.Fw;

namespace Sour
{
    /// <summary>
    /// Automated checks of every engine that can run without administrator rights. All state goes to a scratch
    /// folder (Paths.OverrideRoot); the user's real settings, rules and quarantine are never touched.
    /// Run: Sour.exe --selftest [--out report.txt]
    /// </summary>
    public static class SelfTest
    {
        static int _pass, _fail;
        static readonly StringBuilder Report = new StringBuilder();

        static void Say(string s) { Console.WriteLine(s); Report.AppendLine(s); }
        static void Check(string name, bool ok, string detail = "")
        {
            if (ok) _pass++; else _fail++;
            Say($"{(ok ? "PASS" : "FAIL")}  {name}{(detail == "" ? "" : "  — " + detail)}");
        }
        static void Section(string s) => Say("\n== " + s);
        static void Try(string name, Action a) { try { a(); } catch (Exception ex) { Check(name, false, ex.GetType().Name + ": " + ex.Message); } }

        public static int Run(string[] args)
        {
            string outFile = null;
            for (int i = 0; i < args.Length - 1; i++) if (args[i] == "--out") outFile = args[i + 1];
            string scratch = Path.Combine(Path.GetTempPath(), "sour_selftest_" + Environment.ProcessId);
            Directory.CreateDirectory(scratch);
            Paths.OverrideRoot = Path.Combine(scratch, "root");
            Settings.Reload(); RuleStore.Reload(); Quarantine.Reload(); HashDb.Reload();
            Log.Persist = false;
            var s = Settings.Current;
            s.AvUseAmsi = false;          // AMSI is exercised by --amsi-test; here it would only raise Defender notifications
            s.Language = "en";
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string notepad = Path.Combine(win, "System32", "notepad.exe");
            string kernel32 = Path.Combine(win, "System32", "kernel32.dll");

            try
            {
                Section("WFP firewall engine");
                Try("struct layout", () =>
                {
                    foreach (var (name, actual, expected) in Wfp.StructSizes()) Check($"sizeof({name}) == {expected}", actual == expected, $"actual {actual}");
                });
                Try("app id", () =>
                {
                    string id = Wfp.AppIdString(notepad);
                    Check("FwpmGetAppIdFromFileName0(notepad)", id != null && id.StartsWith("\\device\\") && id.EndsWith("notepad.exe"), id);
                    Check("device path maps back to drive letter", string.Equals(DevicePaths.ToDos(id), notepad, StringComparison.OrdinalIgnoreCase), DevicePaths.ToDos(id));
                });
                Try("engine session", () =>
                {
                    try
                    {
                        using var w = new Wfp();
                        Check("FwpmEngineOpen0", true);
                        try { var own = w.EnumOwnFilters(); Check("enumerate Sour filters (template + FWPM_FILTER0 read-back)", true, own.Count + " installed"); }
                        catch (WfpException ex) when (ex.Code == 5) { Check("enumerate Sour filters", true, "access denied without admin (expected)"); }
                    }
                    catch (WfpException ex) when (ex.Code == 5) { Check("FwpmEngineOpen0", true, "access denied without admin (expected)"); }
                });
                Try("policy → filters", () =>
                {
                    var st = new RuleStore();
                    st.Apps.Add(new AppRule { Path = notepad, Name = "notepad.exe", Action = RuleAction.Allow, AllowInbound = true });
                    st.Apps.Add(new AppRule { Path = kernel32, Name = "blocked", Action = RuleAction.Block });
                    st.Apps.Add(new AppRule { Path = @"C:\x\expired.exe", Name = "expired", Action = RuleAction.Allow, Expires = DateTime.Now.AddMinutes(-1) });
                    st.Apps.Add(new AppRule { Path = @"C:\x\changed.exe", Name = "changed", Action = RuleAction.Allow, HashChanged = true });
                    st.BlockedIps.Add(new IpRule { Cidr = "203.0.113.0/24" });
                    st.BlockedIps.Add(new IpRule { Cidr = "2001:db8::/32" });
                    var set = new Settings();
                    set.FirewallMode = FwMode.Off; Check("Off → no filters", FirewallEngine.BuildSpecs(set, st, DateTime.Now).Count == 0);
                    set.FirewallMode = FwMode.Monitor; Check("Monitor → no filters", FirewallEngine.BuildSpecs(set, st, DateTime.Now).Count == 0);
                    set.FirewallMode = FwMode.Lockdown;
                    var lk = FirewallEngine.BuildSpecs(set, st, DateTime.Now);
                    Check("Lockdown → only loopback permits + block-all", lk.Count == 8 && lk.Count(f => f.Block) == 4 && lk.Where(f => !f.Block).All(f => f.Loopback));
                    set.FirewallMode = FwMode.Whitelist;
                    var wl = FirewallEngine.BuildSpecs(set, st, DateTime.Now);
                    Check("Whitelist: default-deny outbound (v4+v6)", wl.Count(f => f.Block && f.Outbound && f.AppPath == null && f.Weight == FirewallEngine.WDefault && !f.V4Addr.HasValue && f.V6Addr == null) == 2);
                    Check("Whitelist: allowed app permitted", wl.Count(f => !f.Block && f.Outbound && f.AppPath == notepad) == 2);
                    Check("Whitelist: inbound permit for server app", wl.Count(f => !f.Block && !f.Outbound && f.AppPath == notepad) == 2);
                    Check("Whitelist: blocked app has top weight", wl.Where(f => f.AppPath == kernel32).All(f => f.Block && f.Weight == FirewallEngine.WBlockApp) && wl.Count(f => f.AppPath == kernel32) == 4);
                    Check("expired and hash-changed rules are not installed", !wl.Any(f => f.AppPath != null && (f.AppPath.Contains("expired") || f.AppPath.Contains("changed"))));
                    Check("IP block list above app permits", wl.Count(f => f.Block && f.Weight == FirewallEngine.WBlockIp) == 4 && FirewallEngine.WBlockIp > FirewallEngine.WAllowApp);
                    var v4 = wl.First(f => f.Block && f.V4Addr.HasValue && f.Outbound);
                    Check("CIDR 203.0.113.0/24 → addr/mask", v4.V4Addr == 0xCB007100 && v4.V4Mask == 0xFFFFFF00, $"{v4.V4Addr:X8}/{v4.V4Mask:X8}");
                    Check("core services (DNS/DHCP/NTP) present", wl.Any(f => f.RemotePort == 53 && f.Protocol == 17) && wl.Any(f => f.RemotePort == 67) && wl.Any(f => f.RemotePort == 123));
                    set.FwAllowCoreServices = false; set.FwAllowLan = false; set.FwBlockInbound = false;
                    var strict = FirewallEngine.BuildSpecs(set, st, DateTime.Now);
                    Check("strict whitelist has no core/LAN/inbound filters", !strict.Any(f => f.Weight == FirewallEngine.WCore || f.Weight == FirewallEngine.WLan) && strict.Where(f => !f.Outbound).All(f => f.Loopback || f.Weight >= FirewallEngine.WBlockIp));
                    set.FirewallMode = FwMode.Blocklist; set.FwBlockInbound = true;
                    var bl = FirewallEngine.BuildSpecs(set, st, DateTime.Now);
                    Check("Blocklist: no default-deny outbound", !bl.Any(f => f.Block && f.Outbound && f.Weight == FirewallEngine.WDefault));
                    Check("Blocklist: stealth inbound present", bl.Count(f => f.Block && !f.Outbound && f.Weight == FirewallEngine.WDefault) == 2);
                    Check("bad CIDR rejected", !FirewallEngine.TryParseCidr("10.0.0.0/40", out _, out _) && !FirewallEngine.TryParseCidr("nonsense", out _, out _) && FirewallEngine.TryParseCidr("8.8.8.8", out _, out int p32) && p32 == 32);
                });

                Section("PE parser + ML model");
                PeFile peN = null;
                Try("pe parse", () =>
                {
                    peN = PeFile.Parse(File.ReadAllBytes(notepad));
                    Check("notepad.exe parses", peN.Valid && peN.Is64 && peN.Sections.Count >= 4 && peN.Imports.Count >= 5, $"{peN.Sections.Count} sections, {peN.Imports.Count} import DLLs");
                    var k = PeFile.Parse(File.ReadAllBytes(kernel32));
                    Check("kernel32.dll exports", k.Valid && k.IsDll && k.ExportCount > 1000, k.ExportCount + " exports");
                    Check("garbage is rejected", !PeFile.Parse(new byte[4096]).Valid && !PeFile.Parse(Encoding.ASCII.GetBytes("MZ" + new string('x', 200))).Valid);
                    var x = PeFeatures.Extract(peN);
                    Check("feature vector length", x.Length == PeFeatures.Names.Length && x.Length == 193, x.Length.ToString());
                    Check("features finite", x.All(v => !double.IsNaN(v) && !double.IsInfinity(v)));
                });
                Try("ml", () =>
                {
                    var m = MlModel.Instance;
                    Check("model loaded", m.Loaded, m.Loaded ? $"{m.File.trees.Length} trees, thresholds {m.File.threshold_suspicious:0.000}/{m.File.threshold_malicious:0.000}" : "missing");
                    Check("model card loaded", m.Card != null && m.Card.test_auc > 0.9, m.Card == null ? "" : $"test AUC {m.Card.test_auc:0.0000}");
                    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(Paths.DataDir, "parity.json")));
                    double maxDiff = 0, maxExplain = 0; int n = 0, agree = 0;
                    foreach (var row in doc.RootElement.GetProperty("rows").EnumerateArray())
                    {
                        double[] x = row.GetProperty("x").EnumerateArray().Select(e => e.GetDouble()).ToArray();
                        double want = row.GetProperty("p").GetDouble();
                        double got = m.Predict(x);
                        maxDiff = Math.Max(maxDiff, Math.Abs(got - want));
                        maxExplain = Math.Max(maxExplain, Math.Abs(m.Explain(x).Prob - got));
                        if ((got >= m.File.threshold_malicious) == (row.GetProperty("y").GetInt32() == 1)) agree++;
                        n++;
                    }
                    Check("C# inference == LightGBM (300 held-out rows)", n == 300 && maxDiff < 1e-9, $"max |Δp| = {maxDiff:E2}");
                    Check("explanation path gives the same probability", maxExplain < 1e-9, $"max |Δ| = {maxExplain:E2}");
                    Say($"      held-out agreement at the malicious threshold: {agree}/{n}");
                });

                Section("signature rules");
                Try("rules", () =>
                {
                    var eng = RuleEngine.Instance;
                    Check("rule file loaded", eng.Rules.Count >= 40, eng.Rules.Count + " rules");
                    int fired = 0, withStrings = 0; var missed = new List<string>();
                    foreach (var r in eng.Rules.Where(r => r.strings.Count > 0 && (r.imports_all == null || r.imports_all.Length == 0)))
                    {
                        withStrings++;
                        // synthesise a sample from the rule's own first alternatives
                        var ms = new MemoryStream();
                        foreach (string g in r.strings.Keys) { var (b, _, _) = RuleEngine.Decode(r.Alternatives(g).First()); ms.Write(b); ms.WriteByte((byte)'\n'); }
                        string ext = r.ext != null && r.ext.Length > 0 ? r.ext[0] : (r.target == "script" ? ".ps1" : r.target == "lnk" ? ".lnk" : ".bin");
                        string kind = r.target == "any" ? (ext == ".bin" ? "other" : "script") : r.target;
                        if (eng.Scan(ms.ToArray(), kind, ext, false, null).Any(h => h.Rule.id == r.id)) fired++; else missed.Add(r.id);
                    }
                    Check("every string rule fires on its own sample", fired == withStrings, $"{fired}/{withStrings} {string.Join(",", missed)}");
                    string benign = "Dear team, please find the quarterly report attached. The meeting is on Monday at ten. Regards.";
                    Check("benign text fires nothing", eng.Scan(Encoding.UTF8.GetBytes(benign), "other", ".txt", false, null).Count == 0);
                    var sample = eng.Rules.First(r => r.id == "SOUR.PS.DownloadExec");
                    var one = RuleEngine.Decode(sample.Alternatives("dl").First()).bytes;
                    Check("AND condition: one group alone does not fire", !eng.Scan(one, "script", ".ps1", false, null).Any(h => h.Rule.id == sample.id));
                    var wide = Encoding.Unicode.GetBytes(Encoding.UTF8.GetString(RuleEngine.Decode(eng.Rules.First(r => r.id == "SOUR.Cred.Mimikatz").Alternatives("a").First()).bytes).ToUpperInvariant());
                    Check("UTF-16 + case-insensitive match", eng.Scan(wide, "other", ".bin", false, null).Any(h => h.Rule.id == "SOUR.Cred.Mimikatz"));
                    Check("unsigned_only rule skipped for signed file", !eng.Scan(wide, "other", ".bin", true, null).Any(h => h.Rule.id == "SOUR.Cred.Mimikatz"));
                    Check("encode/decode round trip", Encoding.UTF8.GetString(RuleEngine.Decode(RuleEngine.Encode("Hello Wall")).bytes) == "Hello Wall");
                });

                Section("scanner");
                byte[] eicar = RuleEngine.Decode(RuleEngine.Instance.Rules.First(r => r.id == "SOUR.Test.EICAR").Alternatives("a").First()).bytes;
                Try("scanner", () =>
                {
                    var sc = Scanner.Instance;
                    var r1 = sc.ScanBuffer(eicar, "eicar.com");
                    Check("EICAR test string (in memory) → Malicious", r1.Verdict == Verdict.Malicious && r1.Threat == "SOUR.Test.EICAR", $"{r1.Verdict} {r1.Score}");
                    var r2 = sc.ScanFile(notepad);
                    Check("notepad.exe → Clean, trusted", r2.Verdict == Verdict.Clean && r2.SignedValid, $"{r2.Verdict} signer={r2.Signer}");
                    var r3 = sc.ScanBuffer(File.ReadAllBytes(notepad), "invoice.pdf.exe");
                    Check("double extension heuristic", r3.Reasons.Any(x => x.Code == "Heur.DoubleExtension"), $"{r3.Verdict} {r3.Score}");
                    Check("ML scored the unsigned buffer", r3.MlProb >= 0, $"p={r3.MlProb:0.0000}");
                    var r4 = sc.ScanBuffer(File.ReadAllBytes(notepad), "holiday.jpg");
                    Check("disguised executable heuristic", r4.Reasons.Any(x => x.Code == "Heur.DisguisedExecutable"));
                    using (var ms = new MemoryStream())
                    {
                        using (var za = new ZipArchive(ms, ZipArchiveMode.Create, true))
                        {
                            using (var es = za.CreateEntry("docs/readme.txt").Open()) es.Write(Encoding.ASCII.GetBytes("hello"));
                            using (var es = za.CreateEntry("docs/x.com").Open()) es.Write(eicar);
                        }
                        var r5 = sc.ScanBuffer(ms.ToArray(), "bundle.zip");
                        Check("archive member detected", r5.Verdict == Verdict.Malicious && r5.Reasons.Any(x => x.Code.StartsWith("Archive.")), r5.Summary);
                    }
                    var big = new StringBuilder("$a = '"); big.Append('Q', 3000); big.Append("'\n");
                    for (int i = 0; i < 30; i++) big.Append("$x += [char]").Append(65 + i % 26).Append('\n');
                    var r6 = sc.ScanBuffer(Encoding.UTF8.GetBytes(big.ToString()), "x.ps1");
                    Check("script obfuscation heuristics", r6.Reasons.Any(x => x.Code == "Heur.Script.Base64Blob") && r6.Reasons.Any(x => x.Code == "Heur.Script.CharCodes") && r6.Verdict == Verdict.Suspicious, $"{r6.Verdict} {r6.Score}");
                    string h = Util.Sha256(Encoding.ASCII.GetBytes("sour-hash-test"));
                    HashDb.AddUser(h, "selftest");
                    Check("hash block list", sc.ScanBuffer(Encoding.ASCII.GetBytes("sour-hash-test"), "a.bin").Verdict == Verdict.Malicious);
                });
                Try("trust", () =>
                {
                    var t = Trust.Check(notepad);
                    Check("notepad.exe: valid Windows signature", t.Valid && t.IsMicrosoft, t.Describe());
                    string self = Environment.ProcessPath;
                    var ts = Trust.Check(Path.Combine(AppContext.BaseDirectory, "Sour.dll"));
                    Check("unsigned file reported as unsigned", !ts.Valid && !ts.Embedded, ts.Describe());
                });
                Try("quarantine", () =>
                {
                    string f = Path.Combine(scratch, "sample.bin");
                    var content = Encoding.ASCII.GetBytes("harmless quarantine round-trip sample " + Guid.NewGuid());
                    File.WriteAllBytes(f, content);
                    var res = new ScanResult { Path = f, Verdict = Verdict.Malicious, Score = 90, Sha256 = Util.Sha256(content) };
                    var q = Quarantine.Add(res);
                    Check("file removed and stored encrypted", q.ok && !File.Exists(f) && Quarantine.Items.Count == 1, q.error ?? "");
                    byte[] blob = File.ReadAllBytes(Path.Combine(Paths.Quarantine, q.item.Id + ".sourq"));
                    Check("stored copy is not the plaintext", !Encoding.ASCII.GetString(blob).Contains("harmless quarantine"));
                    var back = Quarantine.Restore(q.item.Id);
                    Check("restore is byte-identical", back.ok && File.ReadAllBytes(f).SequenceEqual(content) && Quarantine.Items.Count == 0, back.error ?? "");
                });

                Section("network AI");
                Try("anomaly", () =>
                {
                    var ai = new NetAnomaly(); ai.Reset();
                    var t0 = new DateTime(2026, 1, 5, 10, 0, 0);
                    double maxLearn = 0;
                    var rnd = new Random(11); var t = t0;
                    for (int i = 0; i < 80; i++)
                    {
                        t = t.AddSeconds(3 + rnd.Next(240));          // human-paced, irregular browsing
                        var c = new Conn { Pid = 1, ProcessPath = @"C:\app\browser.exe", Protocol = "TCP", Remote = IPAddress.Parse("93.184.216." + (10 + rnd.Next(5))), RemotePort = 443, Host = "example.com" };
                        maxLearn = Math.Max(maxLearn, ai.Observe(c, t).Score);
                    }
                    Check("normal traffic stays quiet", maxLearn < 30, $"max score {maxLearn:0}");
                    var odd = new Conn { Pid = 1, ProcessPath = @"C:\app\browser.exe", Protocol = "TCP", Remote = IPAddress.Parse("198.51.100.7"), RemotePort = 4444 };
                    var v = ai.Observe(odd, t0.AddHours(17));
                    Check("rare port + new network + odd hour + raw IP → alert", v.Score >= 70, $"score {v.Score:0}: {v.Why}");
                    NetVerdict beacon = null;
                    for (int i = 0; i < 12; i++)
                        beacon = ai.Observe(new Conn { Pid = 2, ProcessPath = @"C:\app\updater.exe", Protocol = "TCP", Remote = IPAddress.Parse("203.0.113.9"), RemotePort = 443, Host = "cdn.example.net" }, t0.AddSeconds(i * 60));
                    Check("beaconing (60 s period) detected", beacon.Reasons.Any(x => x.Contains("beacon")), $"score {beacon.Score:0}");
                    Check("private addresses are not scored as external", ai.Observe(new Conn { Pid = 3, ProcessPath = @"C:\app\lan.exe", Remote = IPAddress.Parse("192.168.1.20"), RemotePort = 4444 }, t0).Score == 0);
                });
                Try("dga", () =>
                {
                    string[] good = { "www.google.com", "login.microsoftonline.com", "en.wikipedia.org", "github.com", "mail.yahoo.co.uk", "stackoverflow.com", "www.aljazeera.net" };
                    string[] bad = { "xkqzvbnmtrplwq.com", "a8f3k2j9d0s1qz7x.net", "qwrtzpsdfgkl.biz", "zx9c8v7b6n5m4q3w.info" };
                    Check("ordinary domains score low", good.All(g => Dga.Score(g) < 0.5), string.Join(" ", good.Select(g => Dga.Score(g).ToString("0.00"))));
                    Check("generated-looking domains score high", bad.All(g => Dga.Score(g) >= 0.6), string.Join(" ", bad.Select(g => Dga.Score(g).ToString("0.00"))));
                    Check("core label extraction", Dga.CoreLabel("mail.yahoo.co.uk") == "yahoo" && Dga.CoreLabel("a.b.example.com") == "example");
                });
                Try("live tables", () =>
                {
                    var snap = ConnMonitor.Snapshot();
                    Check("connection table readable", snap.Count > 0 && snap.Any(c => !string.IsNullOrEmpty(c.ProcessPath)), $"{snap.Count} endpoints, {snap.Count(c => !c.IsListener)} connections");
                    int names = 0;
                    for (int i = 0; i < 40; i++) names = DnsCache.Names().Count;
                    Check("DNS cache read 40× without fault", true, names + " cached names");
                    Check("DNS map built", DnsCache.Map() != null, DnsCache.Map().Count + " address→name pairs");
                    Check("own command line readable", (Proc.CommandLine(Environment.ProcessId) ?? "").Contains("--selftest"));
                });

                Section("auto-pilot");
                Try("autopilot", () =>
                {
                    var a = AutoPilotEngine.Assess(notepad);
                    Check("Windows component → allow", a.Advice == "allow" && a.Trust.IsMicrosoft, a.WhyEn);
                    s.FwAutoPilot = AutoPilot.Assist; s.FwTrustMicrosoft = true;
                    Check("Assist mode may auto-allow it", AutoPilotEngine.MayAct(a));
                    var miss = AutoPilotEngine.Assess(@"C:\does\not\exist.exe");
                    Check("missing file → ask", miss.Advice == "ask" && !AutoPilotEngine.MayAct(miss));
                    s.FwAutoPilot = AutoPilot.Off;
                    Check("auto-pilot Off never acts", !AutoPilotEngine.MayAct(a));
                    s.FwAutoPilot = AutoPilot.Assist;
                    var bw = new BlockWatcher();
                    bw.Record(notepad, "93.184.216.34:443", false);
                    for (int i = 0; i < 50 && RuleStore.Current.Find(notepad) == null; i++) Thread.Sleep(100);
                    var rule = RuleStore.Current.Find(notepad);
                    Check("blocked Windows binary gets an auto-pilot allow rule with pinned hash", rule != null && rule.Action == RuleAction.Allow && rule.Source == "autopilot" && rule.Hash?.Length == 64);
                    string unknown = Path.Combine(AppContext.BaseDirectory, "Sour.dll");
                    bw.Record(unknown, "198.51.100.1:8080", false);
                    for (int i = 0; i < 50 && (!bw.Pending.ContainsKey(unknown) || bw.Pending[unknown].Assessment == null); i++) Thread.Sleep(100);
                    Check("unsigned program stays pending for the user", bw.Pending.ContainsKey(unknown) && RuleStore.Current.Find(unknown) == null, bw.Pending.ContainsKey(unknown) ? bw.Pending[unknown].Assessment?.WhyEn : "");
                    bw.Decide(unknown, RuleAction.Block);
                    Check("user decision stored", RuleStore.Current.Find(unknown)?.Action == RuleAction.Block && !bw.Pending.ContainsKey(unknown));
                    // hash pinning
                    string app = Path.Combine(scratch, "pinned.exe");
                    File.WriteAllBytes(app, File.ReadAllBytes(unknown));
                    FirewallEngine.SetRule(app, RuleAction.Allow);
                    Check("pin holds while the file is unchanged", FirewallEngine.VerifyPins().Count == 0);
                    File.AppendAllText(app, "tampered");
                    var ch = FirewallEngine.VerifyPins();
                    Check("changed binary suspends its allow rule", ch.Count == 1 && RuleStore.Current.Find(app).HashChanged);
                });

                Section("security audit");
                Try("audit", () =>
                {
                    var items = Audit.Run();
                    Check("hardening checks run", items.Count >= 15 && items.All(i => !string.IsNullOrEmpty(i.En) && !string.IsNullOrEmpty(i.Ar) && !string.IsNullOrEmpty(i.FoundEn)), items.Count + " checks, " + items.Count(i => i.State == AuditState.Bad) + " bad, " + items.Count(i => i.State == AuditState.Unknown) + " unreadable");
                    Check("every failed check comes with a fix", items.Where(i => i.State == AuditState.Bad).All(i => !string.IsNullOrEmpty(i.FixEn) && !string.IsNullOrEmpty(i.FixAr)));
                    int sc = Audit.Score(items);
                    Check("score within 0..100", sc >= 0 && sc <= 100, sc.ToString());
                    var st = Audit.Startup();
                    Check("startup inventory scanned", st != null, st.Count + " entries, " + st.Count(e => e.Missing) + " with a missing target");
                    string html = Audit.HtmlReport(items, st, new List<ScanResult>());
                    Check("HTML report is well formed", html.StartsWith("<!doctype html>") && html.EndsWith("</html>") && html.Contains("<table>") && items.All(i => html.Contains(System.Net.WebUtility.HtmlEncode(i.En))));
                });

                Section("extras");
                Try("extras", () =>
                {
                    string ud = Path.Combine(scratch, "UserData"), ver = Path.Combine(ud, "Default", "Extensions", "abcdefghijklmnop", "1.2_0");
                    Directory.CreateDirectory(Path.Combine(ver, "_locales", "en"));
                    File.WriteAllText(Path.Combine(ver, "manifest.json"), "{\"name\":\"__MSG_appName__\",\"version\":\"1.2\",\"default_locale\":\"en\",\"permissions\":[\"cookies\",\"storage\"],\"host_permissions\":[\"<all_urls>\"]}");
                    File.WriteAllText(Path.Combine(ver, "_locales", "en", "messages.json"), "{\"appname\":{\"message\":\"Coupon Helper\"}}");
                    string ver2 = Path.Combine(ud, "Default", "Extensions", "qrstuvwxyzabcdef", "3.0_0"); Directory.CreateDirectory(ver2);
                    File.WriteAllText(Path.Combine(ver2, "manifest.json"), "{\"name\":\"Dark Theme\",\"version\":\"3.0\",\"permissions\":[\"storage\"]}");
                    var exts = Extras.BrowserExtensions(new[] { ("Test", ud) });
                    Check("extension manifests parsed, localised name resolved", exts.Count == 2 && exts[0].Name == "Coupon Helper" && exts[0].Version == "1.2", string.Join(" | ", exts.Select(x => x.Name + ":" + x.Risk)));
                    Check("all-sites + cookies rated high, storage-only rated low", exts[0].Risk == 2 && exts[0].AllSites && exts[1].Risk == 0);
                    Check("real browser profiles readable", Extras.BrowserExtensions() != null, Extras.BrowserExtensions().Count + " extensions installed");
                    string arp = "Interface: 192.168.1.5 --- 0x12\n  Internet Address      Physical Address      Type\n  192.168.1.1           20-9a-7d-5c-4f-b5     dynamic\n  192.168.1.44          a4-83-e7-11-22-33     dynamic\n  224.0.0.22            01-00-5e-00-00-16     static\n  255.255.255.255       ff-ff-ff-ff-ff-ff     static\n";
                    var devs = Extras.ParseArp(arp, new HashSet<string> { "192.168.1.1" });
                    Check("ARP table parsed, multicast and broadcast dropped, gateway marked", devs.Count == 2 && devs[0].Gateway && devs[0].Ip == "192.168.1.1" && devs[1].Mac == "a4-83-e7-11-22-33");
                    var first = Extras.LanDevices(); var again = Extras.LanDevices();
                    Check("live neighbour list; known devices are not new on the second look", again.All(d => !d.IsNew), first.Count + " neighbours");
                    string victim = Path.Combine(scratch, "secret.txt");
                    File.WriteAllText(victim, new string('S', 5000));
                    var sh = Extras.Shred(victim);
                    Check("shredded file is gone", sh.ok && !File.Exists(victim) && Directory.GetFiles(scratch).All(f => new FileInfo(f).Length != 5000 || !File.ReadAllText(f).StartsWith("SSSS")), sh.error ?? "");
                    Check("shredding a missing file reports an error", !Extras.Shred(victim).ok);
                });

                Section("live guards");
                Try("file guard", () =>
                {
                    string watch = Path.Combine(scratch, "watched"); Directory.CreateDirectory(watch);
                    s.AvWatchFolders = new List<string> { watch };
                    s.AvRealtime = true; s.AvOnMalicious = AvAction.Quarantine;
                    Detection got = null;
                    Guard.Instance.Detected += d => got = d;
                    Guard.Instance.Sync();
                    string drop = Path.Combine(watch, "dropped.com");
                    File.WriteAllBytes(drop, Encoding.ASCII.GetBytes("sour-hash-test"));      // on the hash block list from the scanner test
                    for (int i = 0; i < 80 && got == null; i++) Thread.Sleep(100);
                    Check("new file detected by the file guard", got != null && got.Source == "file guard", got?.Result.Summary ?? "nothing within 8 s");
                    Check("auto-quarantine removed it", got != null && got.State == "quarantined" && !File.Exists(drop), got?.State ?? "");
                    s.AvRealtime = false; Guard.Instance.Sync();
                    Check("file guard stops", !Guard.Instance.FileGuardOn);
                });
                Try("ransomware shield", () =>
                {
                    string docs = Path.Combine(scratch, "docs"); Directory.CreateDirectory(docs);
                    Guard.ProtectedOverride = new List<string> { docs };
                    s.AvRansomShield = true; s.AvOnMalicious = AvAction.ReportOnly;
                    var seen = new List<SecEvent>();
                    Action<SecEvent> h = e => { if (e.Kind == EventKind.Ransomware) lock (seen) seen.Add(e); };
                    Log.Added += h;
                    Guard.Instance.Sync();
                    var canaries = Guard.CanaryFiles();
                    Check("decoy files placed (hidden)", canaries.Count == 2 && canaries.All(File.Exists) && canaries.All(c => (File.GetAttributes(c) & FileAttributes.Hidden) != 0));
                    Thread.Sleep(300);
                    File.SetAttributes(canaries[0], FileAttributes.Normal);
                    File.WriteAllText(canaries[0], "ENCRYPTED");
                    for (int i = 0; i < 60 && !seen.Any(e => e.Code == "rs.alert"); i++) Thread.Sleep(100);
                    Check("touching a decoy raises a critical alert", seen.Any(e => e.Code == "rs.alert" && e.Level == Severity.Critical), seen.LastOrDefault()?.TitleEn ?? "none");
                    Thread.Sleep(16000);      // alert throttle window
                    lock (seen) seen.Clear();
                    for (int i = 0; i < 40; i++) File.WriteAllText(Path.Combine(docs, $"report{i}.docx"), "data");
                    for (int i = 0; i < 40; i++) File.Move(Path.Combine(docs, $"report{i}.docx"), Path.Combine(docs, $"report{i}.docx.locked"));
                    for (int i = 0; i < 60 && !seen.Any(e => e.Code == "rs.alert"); i++) Thread.Sleep(100);
                    Check("mass extension change raises an alert", seen.Any(e => e.Code == "rs.alert"), seen.LastOrDefault()?.TitleEn ?? "none");
                    s.AvRansomShield = false; Guard.Instance.Sync();
                    Check("decoys removed when the shield is switched off", canaries.All(c => !File.Exists(c)));
                    Log.Added -= h;
                });
                Try("persistence", () =>
                {
                    var auto = Guard.Autoruns();
                    Check("autorun inventory readable", auto != null, auto.Count + " entries");
string enc = Convert.ToBase64String(Encoding.Unicode.GetBytes("Get-Date | Out-Null"));
                    Check("encoded PowerShell command is decoded", Guard.DecodeEncodedCommand("powershell.exe -NoProfile -EncodedCommand " + enc) == "Get-Date | Out-Null" && Guard.DecodeEncodedCommand("pwsh -enc " + enc) == "Get-Date | Out-Null" && Guard.DecodeEncodedCommand("powershell -File a.ps1") == "");
                    Check("command target parsing", Guard.CommandTarget("\"C:\\Program Files\\App\\a.exe\" --silent") == "C:\\Program Files\\App\\a.exe" && Guard.CommandTarget("C:\\Tools\\b.exe /tray") == "C:\\Tools\\b.exe");
                });
            }
            finally
            {
                Guard.Instance.StopAll();
                Say($"\nRESULT: {_pass} passed, {_fail} failed");
                if (outFile != null) File.WriteAllText(outFile, Report.ToString(), new UTF8Encoding(false));
                try { Directory.Delete(scratch, true); } catch { }
            }
            return _fail == 0 ? 0 : 1;
        }
    }
}
