using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Sour.Core;

namespace Sour.Fw
{
    /// <summary>
    /// Lexical score for algorithmically generated domain names (DGA). A small logistic model over
    /// length, character entropy, digit/vowel ratios, consonant runs and common-bigram coverage.
    /// The weights are hand-calibrated (not trained on a corpus) - treat it as an indicator, not a verdict.
    /// </summary>
    public static class Dga
    {
        static readonly HashSet<string> Common = new HashSet<string>((
            "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur " +
            "ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh " +
            "oo go og gl ap pp bo ok fa ce eb yo tu ub wi ki ft am az zo cl ou ud do ck ap pi ne et li nk ed tw ix").Split(' '));

        static readonly HashSet<string> MultiTld = new HashSet<string> { "co", "com", "net", "org", "gov", "edu", "ac" };

        /// <summary>The label an attacker actually chooses: "abc" in www.abc.co.uk.</summary>
        public static string CoreLabel(string host)
        {
            if (string.IsNullOrEmpty(host)) return "";
            var parts = host.Trim('.').ToLowerInvariant().Split('.');
            if (parts.Length < 2) return parts[0];
            int i = parts.Length - 2;
            if (i > 0 && MultiTld.Contains(parts[i]) && parts[parts.Length - 1].Length == 2) i--;
            return parts[i];
        }

        public static double Score(string host)
        {
            string s = CoreLabel(host);
            if (s.Length < 7 || IPAddress.TryParse(host, out _)) return 0;
            var letters = s.Where(char.IsLetter).ToArray();
            double digits = s.Count(char.IsDigit) / (double)s.Length;
            double vowels = letters.Length == 0 ? 0 : letters.Count(c => "aeiou".IndexOf(c) >= 0) / (double)letters.Length;
            int run = 0, maxRun = 0;
            foreach (char c in s) { if (char.IsLetter(c) && "aeiou".IndexOf(c) < 0) { run++; maxRun = Math.Max(maxRun, run); } else run = 0; }
            double ent = Util.Entropy(System.Text.Encoding.ASCII.GetBytes(s));
            int bi = 0, hit = 0;
            for (int i = 0; i + 1 < s.Length; i++) { bi++; if (Common.Contains(s.Substring(i, 2))) hit++; }
            double cover = bi == 0 ? 1 : hit / (double)bi;

            double z = -4.2
                       + 0.10 * Math.Min(s.Length, 30)
                       + 1.15 * Math.Max(ent - 3.0, 0)
                       + 3.2 * digits
                       + 0.55 * Math.Max(maxRun - 3, 0)
                       + 4.6 * Math.Max(0.45 - cover, 0)
                       + 3.0 * Math.Max(0.22 - vowels, 0);
            return 1.0 / (1.0 + Math.Exp(-z));
        }
    }

    public sealed class AppProfile
    {
        public string Path;
        public int Total;
        public Dictionary<int, int> Ports = new Dictionary<int, int>();
        public HashSet<string> Dests = new HashSet<string>();
        public int[] Hours = new int[24];
        public DateTime First = DateTime.Now, Last = DateTime.Now;
    }

    public sealed class ProfileStore { public Dictionary<string, AppProfile> Apps = new Dictionary<string, AppProfile>(StringComparer.OrdinalIgnoreCase); }

    public sealed class NetVerdict
    {
        public double Score;
        public List<string> Reasons = new List<string>();
        public string Why => string.Join(" · ", Reasons);
    }

    /// <summary>
    /// On-device behavioural model of each application's network habits. Nothing is uploaded: the profile
    /// (ports, destination networks, active hours) is learned from this machine only and each new connection
    /// is scored against it. Detects rare ports, new destination networks, odd hours, bursts, beaconing and DGA-like hosts.
    /// </summary>
    public sealed class NetAnomaly
    {
        public static readonly HashSet<int> NotoriousPorts = new HashSet<int> { 4444, 1337, 31337, 6667, 6697, 9001, 9030, 3333, 14444, 5555, 12345, 54321, 2222, 8333 };

        ProfileStore _store = Json.Load<ProfileStore>(Paths.ProfilesFile);
        readonly Dictionary<string, List<DateTime>> _arrivals = new Dictionary<string, List<DateTime>>();
        readonly Dictionary<string, Queue<DateTime>> _recent = new Dictionary<string, Queue<DateTime>>(StringComparer.OrdinalIgnoreCase);
        readonly object _gate = new object();
        DateTime _saved = DateTime.Now;

        public IReadOnlyCollection<AppProfile> Profiles { get { lock (_gate) return _store.Apps.Values.ToList(); } }
        public void Reset() { lock (_gate) { _store = new ProfileStore(); _arrivals.Clear(); _recent.Clear(); Save(); } }
        public void Save() { lock (_gate) { try { Json.Save(Paths.ProfilesFile, _store); } catch { } _saved = DateTime.Now; } }

        public static string DestKey(IPAddress ip)
        {
            if (ip == null) return "";
            var b = ip.GetAddressBytes();
            return ip.AddressFamily == AddressFamily.InterNetwork ? $"{b[0]}.{b[1]}.{b[2]}" : Convert.ToHexString(b, 0, 6);   // /24 or /48
        }

        public static bool IsPrivate(IPAddress ip)
        {
            if (ip == null) return true;
            if (IPAddress.IsLoopback(ip)) return true;
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || b[0] >= 224;
            return ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || (b[0] & 0xFE) == 0xFC;
        }

        /// <summary>Scores a new outbound connection, then learns from it.</summary>
        public NetVerdict Observe(Conn c, DateTime now, bool unsignedUserDir = false)
        {
            var v = new NetVerdict();
            if (c.Remote == null || string.IsNullOrEmpty(c.ProcessPath) || c.Pid == 0 && c.ProcessPath == "System Idle") return v;
            lock (_gate)
            {
                if (!_store.Apps.TryGetValue(c.ProcessPath, out var p)) { p = new AppProfile { Path = c.ProcessPath, First = now }; _store.Apps[c.ProcessPath] = p; }
                int learn = Math.Max(5, Settings.Current.NetAiLearnConnections);
                bool mature = p.Total >= learn;
                bool priv = IsPrivate(c.Remote);
                string dk = DestKey(c.Remote);
                double s = 0;

                if (mature)
                {
                    p.Ports.TryGetValue(c.RemotePort, out int pc);
                    double prob = (pc + 0.5) / (p.Total + 0.5 * Math.Max(p.Ports.Count, 1));
                    double rarity = Math.Clamp(-Math.Log10(prob) / 3.0, 0, 1);
                    if (pc == 0) { s += 12 + 18 * rarity; v.Reasons.Add(I18n.T($"port {c.RemotePort} never used by this app", $"منفذ {c.RemotePort} لم يستخدمه هذا التطبيق من قبل")); }

                    bool concentrated = p.Dests.Count < Math.Max(4, p.Total * 0.3);
                    if (!priv && !p.Dests.Contains(dk) && concentrated)
                    { s += 16; v.Reasons.Add(I18n.T("new destination network for an app that talks to few", "شبكة وجهة جديدة لتطبيق اعتاد وجهات قليلة")); }

                    if (p.Hours[now.Hour] / (double)p.Total < 0.01)
                    { s += 8; v.Reasons.Add(I18n.T($"unusual hour ({now.Hour}:00)", $"ساعة غير معتادة ({now.Hour}:00)")); }
                }

                // burst: connections of this app in the last 60 s against its long-run rate
                if (!_recent.TryGetValue(c.ProcessPath, out var q)) _recent[c.ProcessPath] = q = new Queue<DateTime>();
                q.Enqueue(now);
                while (q.Count > 0 && (now - q.Peek()).TotalSeconds > 60) q.Dequeue();
                double minutes = Math.Max((p.Last - p.First).TotalMinutes, 1);
                double usual = p.Total / minutes;
                if (mature && q.Count >= 40 && q.Count > 8 * Math.Max(usual, 1))
                { s += 14; v.Reasons.Add(I18n.T($"burst: {q.Count} connections in 60 s", $"اندفاع: {q.Count} اتصالاً في 60 ثانية")); }

                if (!priv)
                {
                    double dga = Dga.Score(c.Host);
                    if (dga >= 0.6) { s += 25 * dga; v.Reasons.Add(I18n.T($"host name looks machine-generated ({dga:0.00})", $"اسم النطاق يبدو مولّداً آلياً ({dga:0.00})")); }
                    if (NotoriousPorts.Contains(c.RemotePort))
                    { s += 22; v.Reasons.Add(I18n.T($"port {c.RemotePort} is typical of backdoors, miners or IRC/Tor", $"المنفذ {c.RemotePort} شائع لدى الأبواب الخلفية والمعدِّنات و IRC/Tor")); }
                    if (string.IsNullOrEmpty(c.Host) && c.RemotePort != 443 && c.RemotePort != 80 && c.RemotePort != 53 && c.RemotePort != 853 && c.RemotePort != 123)
                    { s += 10; v.Reasons.Add(I18n.T("direct IP connection (no DNS lookup) on a non-web port", "اتصال مباشر بعنوان IP دون استعلام DNS وعلى منفذ غير ويب")); }

                    // beaconing: regular intervals to the same destination
                    string bk = c.ProcessPath + "|" + c.Remote + "|" + c.RemotePort;
                    if (!_arrivals.TryGetValue(bk, out var arr)) _arrivals[bk] = arr = new List<DateTime>();
                    arr.Add(now);
                    if (arr.Count > 40) arr.RemoveAt(0);
                    if (arr.Count >= 6)
                    {
                        var gaps = new List<double>();
                        for (int i = 1; i < arr.Count; i++) gaps.Add((arr[i] - arr[i - 1]).TotalSeconds);
                        double mean = gaps.Average();
                        double sd = Math.Sqrt(gaps.Sum(g => (g - mean) * (g - mean)) / gaps.Count);
                        if (mean >= 5 && mean <= 3600 && sd / mean < 0.15)
                        { s += 35; v.Reasons.Add(I18n.T($"beaconing: every {mean:0} s (jitter {sd / mean:P0})", $"إشارة دورية كل {mean:0} ثانية (تذبذب {sd / mean:P0})")); }
                    }
                    if (_arrivals.Count > 4000) _arrivals.Clear();
                }

                if (unsignedUserDir && s > 0)
                { s += 25; v.Reasons.Add(I18n.T("unsigned program running from a user-writable folder", "برنامج غير موقَّع يعمل من مجلد قابل للكتابة")); }

                // learn
                p.Total++;
                p.Ports[c.RemotePort] = p.Ports.TryGetValue(c.RemotePort, out int k) ? k + 1 : 1;
                if (p.Dests.Count < 2000) p.Dests.Add(dk);
                p.Hours[now.Hour]++;
                p.Last = now;

                v.Score = Math.Min(100, s);
                if ((now - _saved).TotalMinutes > 3) Save();
            }
            return v;
        }
    }
}
