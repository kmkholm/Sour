using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Threading;
using Sour.Av;
using Sour.Core;

namespace Sour.Fw
{
    public sealed class PendingApp
    {
        public string Path; public string Name;
        public int Attempts; public DateTime First = DateTime.Now, Last = DateTime.Now;
        public string LastRemote; public bool Inbound;
        public AppAssessment Assessment;
    }

    public sealed class AppAssessment
    {
        public string Path; public bool Exists; public TrustInfo Trust; public ScanResult Scan;
        public string Advice;        // allow | block | ask
        public string WhyEn, WhyAr;
        public string Why => I18n.T(WhyEn, WhyAr);
    }

    /// <summary>
    /// The AI auto-pilot. For every program that wants network access it combines the code signature, the antivirus
    /// verdict (rules + ML) and where the file lives, and proposes allow / block / ask.
    /// </summary>
    public static class AutoPilotEngine
    {
        public static AppAssessment Assess(string path)
        {
            var a = new AppAssessment { Path = path, Exists = File.Exists(path), Advice = "ask" };
            if (!a.Exists)
            {
                a.WhyEn = "The program file cannot be found on disk"; a.WhyAr = "ملف البرنامج غير موجود على القرص";
                return a;
            }
            a.Trust = Trust.Check(path);
            a.Scan = Scanner.Instance.ScanFile(path);
            if (a.Scan.Verdict == Verdict.Malicious)
            { a.Advice = "block"; a.WhyEn = "Antivirus verdict: malicious — " + a.Scan.Reasons.OrderByDescending(r => r.Weight).First().En; a.WhyAr = "حكم مكافح الفيروسات: خبيث — " + a.Scan.Reasons.OrderByDescending(r => r.Weight).First().Ar; }
            else if (a.Trust.IsMicrosoft)
            { a.Advice = "allow"; a.WhyEn = "Signed Windows / Microsoft component"; a.WhyAr = "مكوّن ويندوز/مايكروسوفت موقَّع"; }
            else if (a.Scan.Verdict == Verdict.Suspicious)
            { a.Advice = "ask"; a.WhyEn = "Suspicious: " + a.Scan.Summary; a.WhyAr = "مشبوه: " + a.Scan.Summary; }
            else if (a.Trust.Valid)
            { a.Advice = "allow"; a.WhyEn = $"Valid signature ({a.Trust.Publisher}), scan clean" + Ml(a); a.WhyAr = $"توقيع صحيح ({a.Trust.Publisher}) والفحص نظيف" + Ml(a); }
            else
            { a.Advice = "ask"; a.WhyEn = "Unsigned program, scan clean" + Ml(a); a.WhyAr = "برنامج غير موقَّع، الفحص نظيف" + Ml(a); }
            return a;
        }

        static string Ml(AppAssessment a) => a.Scan != null && a.Scan.MlProb >= 0 ? $" · AI {a.Scan.MlProb:P1}" : "";

        /// <summary>true when the auto-pilot level lets Sour act on this advice without asking.</summary>
        public static bool MayAct(AppAssessment a)
        {
            var level = Settings.Current.FwAutoPilot;
            if (level == AutoPilot.Off) return false;
            if (a.Advice == "block") return true;                                  // malware never gets network access
            if (a.Advice != "allow") return false;
            if (level == AutoPilot.Full) return true;
            return a.Trust != null && a.Trust.IsMicrosoft && Settings.Current.FwTrustMicrosoft;   // Assist: only Windows components
        }
    }

    /// <summary>
    /// Listens for connections that Sour's filters dropped (Security log event 5157, enabled through the
    /// "Filtering Platform Connection" audit subcategory) and turns them into allow/block prompts.
    /// Needs administrator rights; without them the firewall still enforces, it just cannot show what it blocked.
    /// </summary>
    public sealed class BlockWatcher
    {
        public static readonly BlockWatcher Instance = new BlockWatcher();
        EventLogWatcher _watcher;
        public readonly Dictionary<string, PendingApp> Pending = new Dictionary<string, PendingApp>(StringComparer.OrdinalIgnoreCase);
        public event Action Changed;
        public long BlockedTotal;
        public string Status = "stopped";
        Timer _applyTimer;

        public bool Running => _watcher != null;

        public void Start()
        {
            if (_watcher != null) return;
            try
            {
                var q = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=5157)]]");
                _watcher = new EventLogWatcher(q);
                _watcher.EventRecordWritten += (_, e) => { try { if (e.EventRecord != null) OnRecord(e.EventRecord); } catch (Exception ex) { Log.Debug("5157: " + ex.Message); } };
                _watcher.Enabled = true;
                Status = "listening";
            }
            catch (Exception ex) { _watcher = null; Status = "unavailable: " + ex.Message; }
        }

        public void Stop() { try { _watcher?.Dispose(); } catch { } _watcher = null; Status = "stopped"; }

        void OnRecord(EventRecord rec)
        {
            using (rec)
            {
                var p = rec.Properties;
                if (p.Count < 10) return;
                // 5157: ProcessID, Application, Direction, SourceAddress, SourcePort, DestAddress, DestPort, Protocol, FilterRTID, LayerName ...
                ulong filterId = Convert.ToUInt64(p[8].Value);
                if (!RuleStore.Current.ActiveFilterIds.Contains(filterId)) return;       // dropped by someone else's filter
                string app = DevicePaths.ToDos(Convert.ToString(p[1].Value));
                bool inbound = Convert.ToString(p[2].Value) == "%%14592";
                string remote = inbound ? $"{p[3].Value}:{p[4].Value}" : $"{p[5].Value}:{p[6].Value}";
                Record(app, remote, inbound);
            }
        }

        /// <summary>Registers one dropped connection attempt (also called directly by tests).</summary>
        public void Record(string app, string remote, bool inbound)
        {
            Interlocked.Increment(ref BlockedTotal);
            if (string.IsNullOrEmpty(app) || app == "System") return;
            var rule = RuleStore.Current.Find(app);
            if (rule != null && rule.Action == RuleAction.Block && rule.Enabled) return;    // explicit block: nothing to ask
            PendingApp pa; bool isNew = false;
            lock (Pending)
            {
                if (!Pending.TryGetValue(app, out pa)) { pa = new PendingApp { Path = app, Name = System.IO.Path.GetFileName(app) }; Pending[app] = pa; isNew = true; }
                pa.Attempts++; pa.Last = DateTime.Now; pa.LastRemote = remote; pa.Inbound = inbound;
            }
            if (!isNew) { Changed?.Invoke(); return; }

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    pa.Assessment = AutoPilotEngine.Assess(app);
                    if (!inbound && AutoPilotEngine.MayAct(pa.Assessment))
                    {
                        bool allow = pa.Assessment.Advice == "allow";
                        FirewallEngine.SetRule(app, allow ? RuleAction.Allow : RuleAction.Block, "autopilot");
                        lock (Pending) Pending.Remove(app);
                        Log.Add(EventKind.Ai, allow ? Severity.Info : Severity.High, allow ? "ap.allow" : "ap.block",
                            $"Auto-pilot {(allow ? "allowed" : "blocked")} {pa.Name}", $"الطيار الآلي {(allow ? "سمح لـ" : "حظر")} {pa.Name}", app + "\n" + pa.Assessment.WhyEn, app);
                        ScheduleApply();
                    }
                    else
                        Log.Add(EventKind.Firewall, Severity.Low, "fw.blocked", $"Blocked {(inbound ? "inbound" : "outbound")} connection of {pa.Name} — decision needed",
                            $"حُجب اتصال {(inbound ? "وارد" : "صادر")} لـ {pa.Name} — بانتظار قرارك", $"{app}\n→ {remote}\n{pa.Assessment.WhyEn}", app);
                }
                catch (Exception ex) { Log.Debug("assess: " + ex.Message); }
                Changed?.Invoke();
            });
        }

        /// <summary>Several auto-pilot decisions in a burst are applied as one transaction.</summary>
        void ScheduleApply()
        {
            _applyTimer?.Dispose();
            _applyTimer = new Timer(_ => { if (Util.IsAdmin()) FirewallEngine.Apply(); }, null, 1200, Timeout.Infinite);
        }

        public void Decide(string app, RuleAction action, int tempMinutes = 0)
        {
            FirewallEngine.SetRule(app, action, "user", tempMinutes);
            lock (Pending) Pending.Remove(app);
            Changed?.Invoke();
        }
    }
}
