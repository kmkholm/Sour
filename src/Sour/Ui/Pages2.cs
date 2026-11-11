using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using Sour.Av;
using Sour.Core;
using Sour.Fw;
using static Sour.Ui.T;

namespace Sour.Ui
{
    public sealed partial class MainWindow
    {
        // ------------------------------------------------------------------ 04 antivirus
        CancellationTokenSource _scanCts;
        Scanner.Progress _scanProgress;
        public List<ScanResult> ScanFindings = new List<ScanResult>();
        string _scanLabel = "";

        public void StartScan(List<string> paths, bool allFiles)
        {
            if (_scanCts != null) return;
            _scanCts = new CancellationTokenSource();
            _scanProgress = new Scanner.Progress();
            ScanFindings = new List<ScanResult>();
            _scanLabel = string.Join(", ", paths.Take(3)) + (paths.Count > 3 ? " …" : "");
            var ct = _scanCts.Token;
            Task.Run(() =>
            {
                var found = Scanner.Instance.ScanPaths(paths, allFiles, p => _scanProgress = new Scanner.Progress { Files = p.Files, Detections = p.Detections, Current = p.Current, Done = p.Done, Seconds = p.Seconds }, ct);
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    ScanFindings = found; _scanCts = null;
                    Log.Add(EventKind.Antivirus, found.Any(f => f.Verdict == Verdict.Malicious) ? Severity.High : Severity.Info, "av.scan_done",
                        $"Scan finished: {_scanProgress.Files} files, {found.Count} flagged", $"انتهى الفحص: {_scanProgress.Files} ملفاً، {found.Count} مشبوهاً", _scanLabel);
                    if (_page == "antivirus") Render();
                }));
            });
            if (_page == "antivirus") Render();
        }

        /// <summary>Detection codes stay stable in logs; on screen they are shown in the user's language.</summary>
        public static string ThreatLabel(string code)
        {
            if (!I18n.IsArabic || string.IsNullOrEmpty(code)) return code;
            if (code.StartsWith("Archive.")) return "داخل أرشيف: " + ThreatLabel(code.Substring(8));
            if (code.StartsWith("SOUR."))
            {
                var rule = RuleEngine.Instance.Rules.FirstOrDefault(x => x.id == code);
                return rule?.ar ?? code;
            }
            return code switch
            {
                "ML.Malicious" => "نموذج الذكاء: خبيث", "ML.Suspicious" => "نموذج الذكاء: مشبوه", "Hash.Blocklist" => "قائمة البصمات المحظورة",
                "AMSI.Detected" => "مزوّد الحماية في النظام", "Behaviour.Ransomware" => "سلوك فدية", "Heur.DoubleExtension" => "امتداد مزدوج",
                "Heur.DisguisedExecutable" => "برنامج متنكّر", "Heur.Packed" => "ملف مضغوط/محمي", "Heur.ModifiedAfterSigning" => "عُدِّل بعد التوقيع",
                "Heur.SystemNameWrongPlace" => "اسم ملف نظام في غير مكانه", "Heur.LookalikeName" => "اسم يقلّد ملف نظام", "Heur.RtlOverride" => "خدعة عكس الاتجاه",
                "Heur.Script.Base64Blob" => "كتلة Base64", "Heur.Script.CharCodes" => "تمويه برموز الحروف", "Heur.EncryptedCode" => "شيفرة مشفّرة",
                "Heur.FewImports" => "استيرادات شبه معدومة", "Heur.WritableEntry" => "شيفرة تعدّل نفسها", "Archive.EncryptedExecutable" => "أرشيف مشفّر فيه برنامج",
                _ => code,
            };
        }

        public static string SourceLabel(string s) => !I18n.IsArabic ? s : s switch
        {
            "file guard" => "حارس الملفات", "process guard" => "حارس العمليات", "usb" => "وسيط USB", "startup" => "بدء التشغيل", "scan" => "فحص", "ransom shield" => "درع الفدية", _ => s,
        };

        public static string StateLabel(string s) => !I18n.IsArabic ? s : s switch
        {
            "quarantined" => "حُجر", "allowed" => "مستثنى", "ignored" => "متجاهَل", "reported" => "أُبلغ عنه", "killed" => "أُنهيت العملية", "pending" => "بانتظار قرارك",
            _ => s.StartsWith("failed") ? "فشل: " + s.Substring(Math.Min(s.Length, 8)) : s,
        };

        bool Confirm(string question) => MessageBox.Show(question, "Sour", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

        static Brush VerdictBrush(Verdict v) => v == Verdict.Malicious ? Red : v == Verdict.Suspicious ? Amber : Moss;
        static string VerdictText(Verdict v) => v switch { Verdict.Malicious => L("MALICIOUS", "خبيث"), Verdict.Suspicious => L("SUSPICIOUS", "مشبوه"), Verdict.Clean => L("CLEAN", "نظيف"), Verdict.Skipped => L("SKIPPED", "متجاوَز"), _ => L("ERROR", "خطأ") };

        /// <summary>One verdict with every reason that contributed to it (the explanation is the product).</summary>
        FrameworkElement ResultCard(ScanResult r, bool actions, Detection det = null)
        {
            var sp = new StackPanel();
            var head = new DockPanel();
            var score = new TextBlock { Text = r.Score.ToString(), FontFamily = Head, FontWeight = FontWeights.Bold, FontSize = 44, Foreground = VerdictBrush(r.Verdict), LineHeight = 44, LineStackingStrategy = LineStackingStrategy.BlockLineHeight, Margin = new Thickness(0, 0, 16, 0), FlowDirection = FlowDirection.LeftToRight };
            DockPanel.SetDock(score, Dock.Left); head.Children.Add(score);
            var hs = new StackPanel();
            var line = new StackPanel { Orientation = Orientation.Horizontal };
            line.Children.Add(Pill(VerdictText(r.Verdict), VerdictBrush(r.Verdict), r.Verdict == Verdict.Suspicious ? Ink : White));
            if (!string.IsNullOrEmpty(r.Threat)) line.Children.Add(Pill(ThreatLabel(r.Threat), Ink));
            if (det != null) line.Children.Add(Pill(SourceLabel(det.Source) + (det.Pid != 0 ? L(" · process frozen", " · العملية مجمَّدة") : ""), Steel));
            if (det != null && det.State != "pending") line.Children.Add(Pill(StateLabel(det.State), Moss));
            hs.Children.Add(line);
            hs.Children.Add(Text(Path.GetFileName(r.Path ?? ""), 15.5, Ink, FontWeights.Bold));
            hs.Children.Add(MonoText(r.Path, 11.5, Steel));
            head.Children.Add(hs);
            sp.Children.Add(head);

            var meta = new List<string>();
            if (r.Size > 0) meta.Add(Util.HumanSize(r.Size));
            if (!string.IsNullOrEmpty(r.Kind)) meta.Add(r.Kind);
            if (!string.IsNullOrEmpty(r.Signer)) meta.Add(L("signer: ", "الموقِّع: ") + r.Signer);
            if (r.MlProb >= 0) meta.Add(L("AI model: ", "نموذج الذكاء: ") + r.MlProb.ToString("P1"));
            if (!string.IsNullOrEmpty(r.Sha256)) meta.Add("sha256 " + r.Sha256.Substring(0, 16) + "…");
            sp.Children.Add(MonoText(string.Join("  ·  ", meta), 11, Steel));

            if (r.Reasons.Count > 0)
            {
                sp.Children.Add(new Border { Height = 10 });
                sp.Children.Add(Label(L("Why", "لماذا")));
                foreach (var why in r.Reasons.OrderByDescending(x => x.Weight))
                {
                    var row = new DockPanel { Margin = new Thickness(0, 0, 0, 5) };
                    var w = new Border { Width = 38, Background = why.Weight >= 80 ? Red : why.Weight >= 40 ? Amber : Hair, Margin = new Thickness(0, 0, 10, 0), VerticalAlignment = VerticalAlignment.Top,
                        Child = new TextBlock { Text = "+" + why.Weight, FontFamily = Mono, FontSize = 11, FontWeight = FontWeights.Bold, Foreground = why.Weight >= 80 ? White : Ink, TextAlignment = TextAlignment.Center, Padding = new Thickness(0, 2, 0, 2) } };
                    DockPanel.SetDock(w, Dock.Left); row.Children.Add(w);
                    row.Children.Add(Text(why.Text, 13, Ink));
                    sp.Children.Add(row);
                }
            }
            if (r.MlTop != null && r.MlTop.Count > 0)
            {
                sp.Children.Add(new Border { Height = 8 });
                sp.Children.Add(Label(L("What pushed the AI model's score up", "ما الذي رفع درجة نموذج الذكاء")));
                double max = r.MlTop.Max(t => t.contribution);
                foreach (var t in r.MlTop) sp.Children.Add(Bar(FeatureLabel(t.name) + " = " + t.value.ToString("0.###"), t.contribution / max, "+" + t.contribution.ToString("0.00")));
            }
            if (!string.IsNullOrEmpty(r.Error)) sp.Children.Add(MonoText(r.Error, 11.5, Red));

            if (actions)
            {
                var wp = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
                bool open = det == null || det.State == "pending";
                if (open && r.Kind != "cmdline" && r.Kind != "behaviour")
                    wp.Children.Add(Button(L("Quarantine", "حجر"), () =>
                    {
                        if (det != null) Guard.Instance.Resolve(det, "quarantine");
                        else { var q = Quarantine.Add(r); if (!q.ok) { Note(q.error); return; } ScanFindings.Remove(r); }
                        Render();
                    }, Kind.Danger, 12.5));
                if (open && det != null && det.Pid != 0)
                    wp.Children.Add(Button(L("End the frozen process", "إنهاء العملية المجمَّدة"), () => { Proc.Kill(det.Pid); det.Pid = 0; det.State = "killed"; Render(); }, Kind.Danger, 12.5));
                if (open)
                    wp.Children.Add(Button(L("It is safe — exclude", "آمن — استثناء"), () =>
                    {
                        if (det != null) Guard.Instance.Resolve(det, "allow");
                        else { if (!Settings.Current.AvExclusions.Contains(r.Path)) { Settings.Current.AvExclusions.Add(r.Path); Settings.Save(); } ScanFindings.Remove(r); }
                        Render();
                    }, Kind.Ghost, 12.5));
                if (open)
                    wp.Children.Add(Button(L("Dismiss", "تجاهل"), () => { if (det != null) Guard.Instance.Resolve(det, "ignore"); else ScanFindings.Remove(r); Render(); }, Kind.Ghost, 12.5));
                if (File.Exists(r.Path ?? ""))
                    wp.Children.Add(Button(L("Show in folder", "إظهار في المجلد"), () => System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + r.Path + "\""), Kind.Ghost, 12.5));
                sp.Children.Add(wp);
            }
            return Card(sp, VerdictBrush(r.Verdict), 16);
        }

        /// <summary>Plain-language names for the model features that most often appear in explanations.</summary>
        public static string FeatureLabel(string f) => f switch
        {
            "coff_DLL" => L("is a DLL (flag)", "مكتبة DLL (علم)"),
            "dd_SECURITY_log" => L("size of the signature block", "حجم كتلة التوقيع"),
            "sec_max_entropy" => L("most random section (entropy)", "أكثر الأقسام عشوائية (إنتروبيا)"),
            "sec_mean_entropy" => L("average section entropy", "متوسط إنتروبيا الأقسام"),
            "file_entropy" => L("whole-file entropy", "إنتروبيا الملف كاملاً"),
            "imp_n_func_log" => L("number of imported functions", "عدد الدوال المستوردة"),
            "imp_n_dll" => L("number of imported DLLs", "عدد المكتبات المستوردة"),
            "str_avlen" => L("average string length", "متوسط طول النصوص"),
            "str_entropy" => L("randomness of text strings", "عشوائية النصوص"),
            "sec_wx" => L("writable + executable sections", "أقسام قابلة للكتابة والتنفيذ"),
            "overlay_entropy" => L("entropy of appended data", "إنتروبيا البيانات الملحقة"),
            "overlay_size_log" => L("size of appended data", "حجم البيانات الملحقة"),
            "checksum_zero" => L("header checksum is zero", "مجموع التحقق صفر"),
            "dd_RESOURCE_log" => L("size of resources", "حجم الموارد"),
            "coff_timestamp" => L("build timestamp", "تاريخ البناء"),
            "opt_image_base_log" => L("preferred load address", "عنوان التحميل المفضّل"),
            "dd_DEBUG_log" => L("debug directory size", "حجم دليل التنقيح"),
            "rich_n_log" => L("compiler (Rich) records", "سجلات المترجم Rich"),
            "sec_nonstd_name" => L("unusual section names", "أسماء أقسام غير معتادة"),
            "entry_entropy" => L("entropy of the code at entry", "إنتروبيا شيفرة نقطة الدخول"),
            _ => f,
        };

        void PageAntivirus()
        {
            var s = Settings.Current;
            // ---- scan launcher
            var scan = new StackPanel();
            var bar = new WrapPanel();
            bool running = _scanCts != null;
            bar.Children.Add(Button(L("Quick scan", "فحص سريع"), () => StartScan(Scanner.QuickScanRoots().ToList(), false), Kind.Primary, 13.5, !running));
            bar.Children.Add(Button(L("Full scan of C:", "فحص كامل للقرص C"), () => StartScan(new List<string> { "C:\\" }, false), Kind.Dark, 13.5, !running));
            bar.Children.Add(Button(L("Scan a folder…", "فحص مجلد…"), () =>
            {
                var d = new Microsoft.Win32.OpenFolderDialog { Title = "Sour" };
                if (d.ShowDialog(this) == true) StartScan(new List<string> { d.FolderName }, true);
            }, Kind.Ghost, 13.5, !running));
            bar.Children.Add(Button(L("Scan a file…", "فحص ملف…"), () =>
            {
                var d = new Microsoft.Win32.OpenFileDialog { Title = "Sour" };
                if (d.ShowDialog(this) == true) { var r = Scanner.Instance.ScanFile(d.FileName, false); ShowResult(r); }
            }, Kind.Ghost, 13.5, !running));
            if (running) bar.Children.Add(Button(L("Stop", "إيقاف"), () => _scanCts?.Cancel(), Kind.Danger, 13.5));
            scan.Children.Add(bar);
            var prog = Text("", 12, Steel);
            var cur = MonoText("", 11, Mute); cur.TextWrapping = TextWrapping.NoWrap; cur.TextTrimming = TextTrimming.CharacterEllipsis;
            scan.Children.Add(prog); scan.Children.Add(cur);
            void Paint()
            {
                var p = _scanProgress;
                if (p == null) { prog.Text = L("Quick scan covers Downloads, Desktop, Temp and the Startup folders (programs, scripts, shortcuts, archives).", "الفحص السريع يشمل التنزيلات وسطح المكتب والمؤقت ومجلدات بدء التشغيل (برامج، سكربتات، اختصارات، أرشيفات)."); return; }
                double rate = p.Seconds > 0 ? p.Files / p.Seconds : 0;
                prog.Text = (p.Done ? L("finished", "انتهى") : L("scanning", "يفحص")) + $" · {p.Files:N0} " + L("files", "ملفاً") + $" · {p.Detections} " + L("flagged", "مشبوهاً") + $" · {p.Seconds:0.0}s · {rate:0}/s";
                cur.Text = p.Done ? _scanLabel : p.Current ?? "";
            }
            Paint();
            Add(Section(L("Scan", "الفحص"), scan, L("Layers: hash block list → signatures → heuristics → AI model → AMSI second opinion.", "الطبقات: قائمة البصمات ← التواقيع ← الاستدلالات ← نموذج الذكاء ← رأي ثانٍ من AMSI.")));

            // ---- live detections
            List<Detection> dets; lock (Guard.Instance.Pending) dets = Guard.Instance.Pending.AsEnumerable().Reverse().Take(30).ToList();
            if (dets.Count > 0)
            {
                Add(H(L("Caught by live protection", "رصدته الحماية الحيّة"), 19));
                var open = dets.Where(d => d.State == "pending").ToList();
                if (open.Count > 1)
                {
                    var la = new WrapPanel();
                    var files = open.Where(d => d.Result.Kind != "cmdline" && d.Result.Kind != "behaviour").ToList();
                    if (files.Count > 0) la.Children.Add(Button(L($"Quarantine all ({files.Count})", $"حجر الكل ({files.Count})"), () =>
                    {
                        if (!Confirm(L($"Move {files.Count} files to quarantine? You can restore them later.", $"نقل {files.Count} ملفاً إلى الحجر الصحي؟ يمكنك استعادتها لاحقاً."))) return;
                        foreach (var d in files) Guard.Instance.Resolve(d, "quarantine");
                        Render();
                    }, Kind.Danger, 12.5));
                    la.Children.Add(Button(L($"All are safe — exclude all ({open.Count})", $"كلها آمنة — استثناء الكل ({open.Count})"), () =>
                    {
                        if (!Confirm(L($"Mark {open.Count} items as safe? Sour will not flag these files again.", $"اعتبار {open.Count} عنصراً آمناً؟ لن ينبّه سور على هذه الملفات مجدداً."))) return;
                        foreach (var d in open) Guard.Instance.Resolve(d, "allow");
                        Render();
                    }, Kind.Ghost, 12.5));
                    la.Children.Add(Button(L($"Dismiss all ({open.Count})", $"تجاهل الكل ({open.Count})"), () => { foreach (var d in open) Guard.Instance.Resolve(d, "ignore"); Render(); }, Kind.Ghost, 12.5));
                    Add(la);
                }
                foreach (var d in dets) Add(ResultCard(d.Result, true, d));
            }
            // ---- scan findings
            if (ScanFindings.Count > 0)
            {
                Add(H(L($"Scan findings ({ScanFindings.Count})", $"نتائج الفحص ({ScanFindings.Count})"), 19));
                var qa = new WrapPanel();
                int mal = ScanFindings.Count(f => f.Verdict == Verdict.Malicious);
                if (mal > 0) qa.Children.Add(Button(L($"Quarantine all {mal} malicious", $"حجر كل الخبيثة ({mal})"), () => { foreach (var f in ScanFindings.Where(f => f.Verdict == Verdict.Malicious).ToList()) if (Quarantine.Add(f).ok) ScanFindings.Remove(f); Render(); }, Kind.Danger, 12.5));
                if (ScanFindings.Count > mal) qa.Children.Add(Button(L($"Quarantine all ({ScanFindings.Count})", $"حجر الكل ({ScanFindings.Count})"), () =>
                {
                    if (!Confirm(L($"Move all {ScanFindings.Count} flagged files to quarantine, including the merely suspicious ones? You can restore them later.", $"نقل كل الملفات المرصودة ({ScanFindings.Count}) إلى الحجر، ومنها المشبوهة فقط؟ يمكنك استعادتها لاحقاً."))) return;
                    int failed = 0;
                    foreach (var f in ScanFindings.ToList()) { if (Quarantine.Add(f).ok) ScanFindings.Remove(f); else failed++; }
                    if (failed > 0) Note(L($"{failed} files could not be moved (in use or already gone).", $"تعذّر نقل {failed} ملفاً (قيد الاستخدام أو غير موجود)."));
                    Render();
                }, Kind.Danger, 12.5));
                qa.Children.Add(Button(L($"All are safe — exclude all ({ScanFindings.Count})", $"كلها آمنة — استثناء الكل ({ScanFindings.Count})"), () =>
                {
                    if (!Confirm(L($"Mark all {ScanFindings.Count} files as safe? Sour will not flag them again.", $"اعتبار كل الملفات ({ScanFindings.Count}) آمنة؟ لن ينبّه سور عليها مجدداً."))) return;
                    foreach (var f in ScanFindings) if (!Settings.Current.AvExclusions.Contains(f.Path)) Settings.Current.AvExclusions.Add(f.Path);
                    Settings.Save(); ScanFindings.Clear(); Render();
                }, Kind.Ghost, 12.5));
                qa.Children.Add(Button(L("Dismiss all", "تجاهل الكل"), () => { ScanFindings.Clear(); Render(); }, Kind.Ghost, 12.5));
                Add(qa);
                foreach (var f in ScanFindings.OrderByDescending(f => f.Score).Take(60)) Add(ResultCard(f, true));
            }
            else if (_scanProgress != null && _scanProgress.Done && dets.Count == 0)
                Add(Card(Text(L("No threats found in the last scan.", "لم يُعثر على تهديدات في آخر فحص."), 15, Moss, FontWeights.Bold), Moss, 14));

            // ---- live protection
            void Opt(Panel host, string en, string ar, string hen, string har, Func<bool> get, Action<bool> set, bool sync = true) =>
                host.Children.Add(Toggle(L(en, ar), L(hen, har), get(), v => { set(v); Settings.Save(); if (sync) Guard.Instance.Sync(); Dispatcher.BeginInvoke(new Action(Render)); }));
            var g1 = new StackPanel(); var g2 = new StackPanel { Margin = new Thickness(24, 0, 0, 0) };
            Opt(g1, "File guard", "حارس الملفات", "Scans programs, scripts, shortcuts and archives the moment they appear in Downloads, Desktop, Documents, Temp, Startup and AppData.", "يفحص البرامج والسكربتات والاختصارات والأرشيفات لحظة ظهورها في التنزيلات وسطح المكتب والمستندات والمؤقت وبدء التشغيل و AppData.", () => s.AvRealtime, v => s.AvRealtime = v);
            Opt(g1, "Process guard", "حارس العمليات", "Checks every program as it starts and inspects script-interpreter command lines. Malicious processes are frozen.", "يفحص كل برنامج عند تشغيله ويدقق أسطر أوامر مفسّرات السكربتات. العمليات الخبيثة تُجمَّد.", () => s.AvProcessWatch, v => s.AvProcessWatch = v);
            Opt(g1, "Ransomware shield", "درع الفدية", "Places hidden decoy files in Documents, Desktop and Pictures; touching them or mass-renaming files raises an alarm and freezes the heaviest writer.", "يضع ملفات طُعم مخفية في المستندات وسطح المكتب والصور؛ لمسها أو إعادة تسمية الملفات جماعياً يطلق إنذاراً ويجمّد أكثر العمليات كتابةً.", () => s.AvRansomShield, v => s.AvRansomShield = v);
            Opt(g2, "USB guard", "حارس USB", "Scans a removable drive when it is plugged in, including autorun.inf.", "يفحص القرص الخارجي عند وصله، ومنه ملف autorun.inf.", () => s.AvUsbScan, v => s.AvUsbScan = v);
            Opt(g2, "Startup watch", "مراقبة بدء التشغيل", "Alerts when a program registers itself to start with Windows or the hosts file changes.", "ينبّه عند تسجيل برنامج نفسه للعمل مع ويندوز أو تغيّر ملف hosts.", () => s.AvPersistenceWatch, v => s.AvPersistenceWatch = v);
            var lg = new UniformGrid { Columns = 2 }; lg.Children.Add(g1); lg.Children.Add(g2);
            var lp = new StackPanel(); lp.Children.Add(lg);
            lp.Children.Add(Label(L("When something malicious is found", "عند العثور على ملف خبيث")));
            lp.Children.Add(Segments(new List<(string, string)> { ("Ask", L("Ask me", "اسألني")), ("Quarantine", L("Quarantine automatically", "حجر تلقائي")), ("ReportOnly", L("Report only", "تقرير فقط")) }, s.AvOnMalicious.ToString(), k => { s.AvOnMalicious = Enum.Parse<AvAction>(k); Settings.Save(); Render(); }));
            lp.Children.Add(MonoText(L($"file guard: {(Guard.Instance.FileGuardOn ? "on" : "off")} · process guard: {(Guard.Instance.ProcessGuardOn ? "on" : "off")} · ransomware shield: {(Guard.Instance.RansomShieldOn ? "on" : "off")} · live scans: {Guard.Instance.RealtimeScans}",
                $"حارس الملفات: {(Guard.Instance.FileGuardOn ? "يعمل" : "متوقف")} · حارس العمليات: {(Guard.Instance.ProcessGuardOn ? "يعمل" : "متوقف")} · درع الفدية: {(Guard.Instance.RansomShieldOn ? "يعمل" : "متوقف")} · فحوص حيّة: {Guard.Instance.RealtimeScans}"), 11.5, Steel));
            Add(Section(L("Live protection", "الحماية الحيّة"), lp, L("Suspicious files are only reported; nothing is deleted without quarantine, and quarantine is reversible.", "الملفات المشبوهة يُبلَّغ عنها فقط؛ لا يُحذف شيء دون حجر، والحجر قابل للتراجع.")));

            _tick = () => { if (_scanCts != null) Paint(); };
        }

        // ------------------------------------------------------------------ 05 quarantine
        public sealed class QRow
        {
            public QuarantineItem Q;
            public string Time { get; } public string Name { get; } public string Threat { get; } public string Score { get; } public string Size { get; } public string Path { get; }
            public QRow(QuarantineItem q) { Q = q; Time = q.Time.ToString("yyyy-MM-dd HH:mm"); Name = System.IO.Path.GetFileName(q.OriginalPath); Threat = ThreatLabel(q.Threat); Score = q.Score.ToString(); Size = Util.HumanSize(q.Size); Path = q.OriginalPath; }
        }

        void PageQuarantine()
        {
            var rows = Quarantine.Items.Select(q => new QRow(q)).ToList();
            var grid = Table(rows, (L("When", "متى"), "Time", 130, true), (L("File", "الملف"), "Name", 180, false), (L("Threat", "التهديد"), "Threat", 210, true), (L("Score", "الدرجة"), "Score", 60, true), (L("Size", "الحجم"), "Size", 80, true), (L("Original location", "الموقع الأصلي"), "Path", -1, true));
            var bar = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
            bar.Children.Add(Button(L("Restore to original location", "استعادة للموقع الأصلي"), () =>
            {
                if (grid.SelectedItem is not QRow x) return;
                if (MessageBox.Show(L("Restore this file? Only do this if you are sure it is safe.\n\n", "استعادة هذا الملف؟ افعل ذلك فقط إن كنت متأكداً أنه آمن.\n\n") + x.Path, "Sour", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                var r = Quarantine.Restore(x.Q.Id); if (!r.ok) Note(r.error);
                else if (!Settings.Current.AvExclusions.Contains(x.Path)) { Settings.Current.AvExclusions.Add(x.Path); Settings.Save(); }
                Render();
            }, Kind.Ghost, 12.5));
            bar.Children.Add(Button(L("Delete permanently", "حذف نهائي"), () =>
            {
                if (grid.SelectedItem is not QRow x) return;
                if (MessageBox.Show(L("Delete this file for good? This cannot be undone.\n\n", "حذف هذا الملف نهائياً؟ لا يمكن التراجع.\n\n") + x.Path, "Sour", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                Quarantine.Delete(x.Q.Id); Render();
            }, Kind.Danger, 12.5));
            if (rows.Count > 1)
            {
                bar.Children.Add(Button(L($"Restore all ({rows.Count})", $"استعادة الكل ({rows.Count})"), () =>
                {
                    if (!Confirm(L($"Restore all {rows.Count} files to where they were? Only do this if you are sure they are safe.", $"استعادة كل الملفات ({rows.Count}) إلى أماكنها؟ افعل ذلك فقط إن كنت متأكداً أنها آمنة."))) return;
                    int failed = 0;
                    foreach (var x in rows)
                    {
                        var r = Quarantine.Restore(x.Q.Id);
                        if (!r.ok) { failed++; continue; }
                        if (!Settings.Current.AvExclusions.Contains(x.Path)) Settings.Current.AvExclusions.Add(x.Path);
                    }
                    Settings.Save();
                    if (failed > 0) Note(L($"{failed} files could not be restored (a file already exists there, or the stored copy is damaged).", $"تعذّرت استعادة {failed} ملفاً (يوجد ملف في المكان نفسه أو النسخة المخزّنة تالفة)."));
                    Render();
                }, Kind.Ghost, 12.5));
                bar.Children.Add(Button(L($"Delete all permanently ({rows.Count})", $"حذف الكل نهائياً ({rows.Count})"), () =>
                {
                    if (!Confirm(L($"Delete all {rows.Count} quarantined files for good? This cannot be undone.", $"حذف كل الملفات المحجورة ({rows.Count}) نهائياً؟ لا يمكن التراجع."))) return;
                    foreach (var x in rows) Quarantine.Delete(x.Q.Id);
                    Render();
                }, Kind.Danger, 12.5));
            }
            var body = new StackPanel();
            body.Children.Add(rows.Count == 0 ? Empty(L("The quarantine is empty.", "الحجر الصحي فارغ.")) : grid);
            if (rows.Count > 0) body.Children.Add(bar);
            Add(Section(L($"Quarantined files ({rows.Count})", $"الملفات المحجورة ({rows.Count})"), body, L("Each file is stored AES-encrypted in Sour's data folder, so it cannot run. A restored file is verified against its SHA-256 and added to the exclusions.", "يُخزَّن كل ملف مشفَّراً بـ AES في مجلد بيانات سور فلا يمكن تشغيله. الملف المستعاد يُتحقق منه ببصمته ويُضاف للاستثناءات.")));
        }

        // ------------------------------------------------------------------ 06 AI centre
        public sealed class ProfRow { public string App { get; set; } public string Total { get; set; } public string Ports { get; set; } public string Nets { get; set; } public string Last { get; set; } public string Path { get; set; } }

        void PageAi()
        {
            var s = Settings.Current; var m = MlModel.Instance;
            if (!m.Loaded || m.Card == null) Add(Card(Text(L("The model file is missing (Data\\sour_model.json). File scanning still works with rules and heuristics.", "ملف النموذج مفقود. الفحص يعمل بالقواعد والاستدلالات."), 14, Red), Red));
            else
            {
                var c = m.Card;
                var top = new StackPanel(); foreach (var st in new[] {
                    Stat(L("Test AUC", "AUC الاختبار"), c.test_auc.ToString("0.0000"), Ink, L("weeks the model never saw", "أسابيع لم يرها النموذج")),
                    Stat(L("Catches (malicious band)", "نسبة الكشف (نطاق الخبيث)"), c.test_at_malicious.tpr.ToString("P1"), Moss, L($"at {c.test_at_malicious.fpr:P2} false alarms", $"عند إنذارات كاذبة {c.test_at_malicious.fpr:P2}")),
                    Stat(L("Catches (with suspicious)", "نسبة الكشف (مع المشبوه)"), c.test_at_suspicious.tpr.ToString("P1"), Amber, L($"at {c.test_at_suspicious.fpr:P2} false alarms", $"عند إنذارات كاذبة {c.test_at_suspicious.fpr:P2}")),
                    Stat(L("Trees × features", "أشجار × خصائص"), c.n_trees + " × " + c.n_features, Ink, c.algorithm) }) top.Children.Add(st);
                Add(Section(L("Measured performance", "الأداء المقاس"), top));

                var card = new StackPanel();
                void Row(string k, string v) { var dp = new DockPanel { Margin = new Thickness(0, 0, 0, 6) }; var kk = Label(k); kk.Width = 190; DockPanel.SetDock(kk, Dock.Left); dp.Children.Add(kk); dp.Children.Add(Text(v, 13)); card.Children.Add(dp); }
                Row(L("Task", "المهمة"), L("Decide from a Windows program's static structure whether it is malware — the file is never run.", "الحكم من البنية الساكنة للبرنامج إن كان خبيثاً — دون تشغيل الملف أبداً."));
                Row(L("Training data", "بيانات التدريب"), c.dataset + L($" — {c.n_train:N0} training, {c.n_val:N0} validation, {c.n_test:N0} test files", $" — {c.n_train:N0} للتدريب، {c.n_val:N0} للتحقق، {c.n_test:N0} للاختبار"));
                Row(L("Sampling", "العيّنة"), L(c.sampling, "أول 2500 سجل PE موسوم من كل ملف أسبوعي (حدّ معلن، وليس كامل المجموعة)"));
                Row(L("Time split", "التقسيم الزمني"), L($"train to {c.train_weeks?[1]}, validate {c.val_weeks?.FirstOrDefault()} → {c.val_weeks?.LastOrDefault()}, test {c.test_weeks?[0]} → {c.test_weeks?[1]}", $"تدريب حتى {c.train_weeks?[1]}، تحقق {c.val_weeks?.FirstOrDefault()} ← {c.val_weeks?.LastOrDefault()}، اختبار {c.test_weeks?[0]} ← {c.test_weeks?[1]}"));
                Row(L("Thresholds", "العتبات"), L($"suspicious ≥ {m.ThresholdSuspicious:0.000}, malicious ≥ {m.ThresholdMalicious:0.000} ({c.threshold_rule})", $"مشبوه ≥ {m.ThresholdSuspicious:0.000}، خبيث ≥ {m.ThresholdMalicious:0.000} (تُحدَّد على بيانات التحقق: 0.1% و 1% إنذارات كاذبة)"));
                Row(L("Trained", "تاريخ التدريب"), c.trained);
                Row(L("Runs", "أين يعمل"), L("Entirely on this PC, in C#. Nothing is uploaded.", "كلياً على هذا الجهاز بلغة C#. لا يُرفع شيء."));
                if (c.per_type != null)
                {
                    card.Children.Add(new Border { Height = 6 });
                    foreach (var kv in c.per_type)
                    {
                        try
                        {
                            double auc = kv.Value.GetProperty("auc").GetDouble(); double tpr = kv.Value.GetProperty("malicious").GetProperty("tpr").GetDouble(); double fpr = kv.Value.GetProperty("malicious").GetProperty("fpr").GetDouble();
                            card.Children.Add(Bar(kv.Key + $"  AUC {auc:0.0000}", tpr, tpr.ToString("P1"), Moss));
                        }
                        catch { }
                    }
                    card.Children.Add(Text(L("Bars: share of malware caught in the malicious band, per file type.", "الأشرطة: نسبة البرمجيات الخبيثة المكتشفة في نطاق «خبيث» لكل نوع ملف."), 12, Steel));
                }
                Add(Section(L("Model card", "بطاقة النموذج"), card, L("Measured, not promised: these figures come from the held-out test weeks.", "أرقام مقاسة لا وعود: مصدرها أسابيع الاختبار المعزولة.")));

                var imp = new StackPanel();
                if (c.top_features != null)
                {
                    double max = c.top_features.Max(f => f.gain);
                    foreach (var f in c.top_features.Take(16)) imp.Children.Add(Bar(FeatureLabel(f.name), f.gain / max, f.gain.ToString("P1")));
                }
                Add(Section(L("What the model looks at most", "أكثر ما ينظر إليه النموذج"), imp, L("Share of the total information gain across all trees.", "حصة كل خاصية من إجمالي الكسب المعلوماتي عبر الأشجار.")));
            }

            // ---- explain a file
            var ex = new StackPanel();
            var exHost = new StackPanel();
            ex.Children.Add(Button(L("Choose a program to explain…", "اختر برنامجاً لشرحه…"), () =>
            {
                var d = new Microsoft.Win32.OpenFileDialog { Filter = "Programs|*.exe;*.dll;*.scr;*.sys|All files|*.*", Title = "Sour" };
                if (d.ShowDialog(this) != true) return;
                var r = Scanner.Instance.ScanFile(d.FileName, false);
                exHost.Children.Clear(); exHost.Children.Add(ResultCard(r, false));
            }, Kind.Primary, 13));
            ex.Children.Add(exHost);
            Add(Section(L("Explain a verdict", "اشرح حكماً"), ex, L("Shows the model's probability and which features pushed it up, next to every rule and heuristic that fired.", "يعرض احتمال النموذج والخصائص التي رفعته، مع كل قاعدة واستدلال انطلق.")));

            // ---- network AI
            var net = new StackPanel();
            net.Children.Add(Toggle(L("Network behaviour model", "نموذج سلوك الشبكة"), L("Learns each program's usual ports, destination networks and active hours on this PC, then scores every new connection: rare port, new network, odd hour, burst, beaconing, machine-generated host name.", "يتعلّم المنافذ والشبكات والساعات المعتادة لكل برنامج على هذا الجهاز، ثم يقيّم كل اتصال جديد: منفذ نادر، شبكة جديدة، ساعة غريبة، اندفاع، إشارة دورية، اسم نطاق مولَّد آلياً."), s.NetAi, v => { s.NetAi = v; Settings.Save(); }));
            net.Children.Add(Label(L("Alert when the risk score reaches", "نبّه عند بلوغ درجة الخطورة")));
            net.Children.Add(Segments(new[] { 50, 60, 70, 80 }.Select(v => (v.ToString(), v.ToString())).ToList(), ((int)s.NetAiAlertScore).ToString(), k => { s.NetAiAlertScore = int.Parse(k); Settings.Save(); Render(); }));
            var profs = Services.NetAi.Profiles.OrderByDescending(p => p.Total).Take(200).Select(p => new ProfRow
            {
                App = Path.GetFileName(p.Path), Total = p.Total.ToString(), Path = p.Path, Nets = p.Dests.Count.ToString(), Last = p.Last.ToString("MM-dd HH:mm"),
                Ports = string.Join(" ", p.Ports.OrderByDescending(kv => kv.Value).Take(5).Select(kv => kv.Key)),
            }).ToList();
            net.Children.Add(new Border { Height = 8 });
            var pg = Table(profs, (L("Program", "البرنامج"), "App", 190, false), (L("Connections", "الاتصالات"), "Total", 90, true), (L("Usual ports", "المنافذ المعتادة"), "Ports", 190, true), (L("Networks", "الشبكات"), "Nets", 80, true), (L("Last seen", "آخر ظهور"), "Last", 110, true), (L("Path", "المسار"), "Path", -1, true));
            pg.MaxHeight = 300;
            net.Children.Add(profs.Count == 0 ? Empty(L("No profiles yet — they build up as programs connect.", "لا ملفات سلوك بعد — تتكوّن مع اتصال البرامج.")) : pg);
            var nb = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
            nb.Children.Add(Button(L("Forget all profiles", "نسيان كل ملفات السلوك"), () => { Services.NetAi.Reset(); Render(); }, Kind.Ghost, 12.5));
            net.Children.Add(nb);
            Add(Section(L($"Network AI ({profs.Count} programs profiled)", $"ذكاء الشبكة ({profs.Count} برنامجاً)"), net, L("Unsupervised and local: it needs about 30 connections per program before judging.", "غير مراقَب ومحلي: يحتاج نحو 30 اتصالاً لكل برنامج قبل أن يحكم.")));

            // ---- DGA tester
            var dga = new StackPanel();
            var din = Input("", 320, "example.com"); var dout = MonoText("", 12.5);
            var dbar = new WrapPanel(); dbar.Children.Add(din);
            dbar.Children.Add(Button(L("Score this host name", "قيّم اسم النطاق"), () => { double v = Dga.Score(din.Text.Trim()); dout.Text = $"{din.Text.Trim()}  →  {v:0.00}  " + (v >= 0.6 ? L("(looks machine-generated)", "(يبدو مولَّداً آلياً)") : L("(looks ordinary)", "(يبدو عادياً)")); }, Kind.Dark, 12.5));
            dga.Children.Add(dbar); dga.Children.Add(dout);
            Add(Section(L("Generated-domain detector", "كاشف النطاقات المولَّدة"), dga, L("A lexical indicator (length, entropy, digits, consonant runs, common letter pairs). An indicator, not proof.", "مؤشر لغوي (الطول، الإنتروبيا، الأرقام، تتابع الصوامت، أزواج الحروف الشائعة). مؤشر لا دليل.")));
        }

        // ------------------------------------------------------------------ security audit
        public sealed class StartRow { public string Where { get; set; } public string Program { get; set; } public string Signer { get; set; } public string Verdict { get; set; } }
        List<AuditItem> _audit; List<StartupEntry> _startup; string _runningNote = "";

        void PageAudit()
        {
            _audit ??= Audit.Run();
            int score = Audit.Score(_audit);
            int bad = _audit.Count(i => i.State == AuditState.Bad), unknown = _audit.Count(i => i.State == AuditState.Unknown);

            var bar = new WrapPanel();
            bar.Children.Add(Button(L("Run the audit again", "إعادة التدقيق"), () => { _audit = Audit.Run(); _startup = null; _exts = null; _devices = null; Render(); }, Kind.Primary, 13));
            bar.Children.Add(Button(L("Scan running programs", "فحص البرامج الجارية"), () =>
            {
                _runningNote = L("scanning running programs…", "يجري فحص البرامج الجارية…"); Render();
                Task.Run(() =>
                {
                    int total = 0;
                    var found = Audit.ScanRunning((n, t) => total = t);
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        foreach (var r in found) if (!ScanFindings.Any(f => f.Path == r.Path)) ScanFindings.Add(r);
                        _runningNote = L($"{total} running programs checked, {found.Count} flagged" + (found.Count > 0 ? " — see the Antivirus page" : ""), $"فُحص {total} برنامجاً جارياً، {found.Count} مشبوهاً" + (found.Count > 0 ? " — انظر صفحة مكافح الفيروسات" : ""));
                        if (_page == "audit") Render();
                    }));
                });
            }, Kind.Dark, 13));
            bar.Children.Add(Button(L("Save report (HTML)…", "حفظ التقرير (HTML)…"), () =>
            {
                var d = new Microsoft.Win32.SaveFileDialog { FileName = "sour-report-" + DateTime.Now.ToString("yyyy-MM-dd") + ".html", Filter = "HTML|*.html" };
                if (d.ShowDialog(this) != true) return;
                File.WriteAllText(d.FileName, Audit.HtmlReport(_audit, _startup ?? Audit.Startup(), ScanFindings), new UTF8Encoding(true));
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(d.FileName) { UseShellExecute = true });
            }, Kind.Ghost, 13));
            var top = new StackPanel();
            top.Children.Add(Text(L($"Hardening score {score}/100 — {bad} to fix, {unknown} could not be read.", $"درجة الصلابة {score}/100 — {bad} بحاجة لإصلاح، {unknown} تعذّرت قراءتها."), 15, bad == 0 ? Moss : Ink, FontWeights.Bold));
            top.Children.Add(new Border { Height = 8 });
            top.Children.Add(bar);
            if (_runningNote != "") top.Children.Add(Text(_runningNote, 12.5, Steel));
            Add(top);

            var list = new StackPanel();
            foreach (var i in _audit.OrderBy(i => i.State == AuditState.Bad ? 0 : i.State == AuditState.Unknown ? 1 : 2).ThenByDescending(i => i.Weight))
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 0) };
                var mark = new Border { Width = 14, Height = 14, Margin = new Thickness(0, 4, 12, 0), VerticalAlignment = VerticalAlignment.Top, Background = i.State == AuditState.Good ? Moss : i.State == AuditState.Bad ? Red : Brushes.Transparent, BorderBrush = i.State == AuditState.Unknown ? Steel : Brushes.Transparent, BorderThickness = new Thickness(2) };
                DockPanel.SetDock(mark, Dock.Left); row.Children.Add(mark);
                var t = new StackPanel();
                t.Children.Add(Text(i.Title, 13.5, Ink, FontWeights.SemiBold));
                t.Children.Add(Text(i.Found, 12.5, i.State == AuditState.Bad ? Red : Steel));
                if (!string.IsNullOrEmpty(i.Fix)) t.Children.Add(Text("← " + i.Fix, 12.5, Ink));
                row.Children.Add(t);
                list.Children.Add(new Border { BorderBrush = Hair, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(0, 8, 0, 8), Child = row });
            }
            Add(Section(L($"System hardening ({_audit.Count} checks)", $"صلابة النظام ({_audit.Count} فحصاً)"), list, L("Read-only: Sour reads these settings and tells you what to change; it changes nothing itself.", "للقراءة فقط: سور يقرأ هذه الإعدادات ويخبرك بما يُغيَّر، ولا يغيّر شيئاً بنفسه.")));

            _startup ??= Audit.Startup();
            var rows = _startup.Select(e => new StartRow
            {
                Where = e.Where, Program = e.Target ?? e.Command, Signer = e.Missing ? L("file not found", "الملف غير موجود") : string.IsNullOrEmpty(e.Signer) ? "—" : e.Signer == "unsigned" ? L("unsigned", "غير موقَّع") : e.Signer == "Windows catalog" ? L("Windows catalog", "كتالوج Windows") : e.Signer,
                Verdict = e.Missing ? "—" : VerdictText(e.Verdict) + (e.Score > 0 ? " " + e.Score : ""),
            }).ToList();
            var sg = Table(rows, (L("Verdict", "الحكم"), "Verdict", 110, false), (L("Signer", "الموقِّع"), "Signer", 210, false), (L("Program", "البرنامج"), "Program", -2, true), (L("Registered in", "مسجَّل في"), "Where", -1, true));
            sg.MaxHeight = 360;
            Add(Section(L($"Programs that start with Windows ({rows.Count})", $"برامج تعمل مع بدء Windows ({rows.Count})"), rows.Count == 0 ? Empty(L("None found.", "لا شيء.")) : sg,
                L("Run keys and Startup folders. Each target is signature-checked and scanned.", "مفاتيح Run ومجلدات بدء التشغيل. كل هدف يُفحص توقيعه ومحتواه.")));
            AuditExtras();
        }

        public sealed class ExtRow { public string Risk { get; set; } public string Browser { get; set; } public string Name { get; set; } public string Version { get; set; } public string Why { get; set; } public string Folder; }
        public sealed class DevRow { public string Ip { get; set; } public string Mac { get; set; } public string Note { get; set; } }
        List<BrowserExtension> _exts; List<LanDevice> _devices;

        void AuditExtras()
        {
            // ---- browser extensions
            _exts ??= Extras.BrowserExtensions();
            var er = _exts.Select(e => new ExtRow
            {
                Risk = e.Risk == 2 ? L("HIGH", "عالٍ") : e.Risk == 1 ? L("medium", "متوسط") : L("low", "منخفض"),
                Browser = e.Browser + (e.Profile == "Default" ? "" : " · " + e.Profile), Name = e.Name, Version = e.Version, Why = e.Why, Folder = e.Folder,
            }).ToList();
            var eg = Table(er, (L("Reach", "مدى الصلاحية"), "Risk", 100, false), (L("Browser", "المتصفح"), "Browser", 130, false), (L("Extension", "الإضافة"), "Name", 260, false), (L("Version", "الإصدار"), "Version", 90, true), (L("What it can do", "ما الذي تستطيعه"), "Why", -1, false));
            eg.MaxHeight = 330;
            var eb = new StackPanel();
            eb.Children.Add(er.Count == 0 ? Empty(L("No Chrome, Edge or Brave extensions found.", "لا إضافات في Chrome أو Edge أو Brave.")) : eg);
            var ebar = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
            ebar.Children.Add(Button(L("Open the extension's folder", "فتح مجلد الإضافة"), () => { if (eg.SelectedItem is ExtRow x && Directory.Exists(x.Folder)) System.Diagnostics.Process.Start("explorer.exe", x.Folder); }, Kind.Ghost, 12.5));
            eb.Children.Add(ebar);
            Add(Section(L($"Browser extensions ({er.Count}, {_exts.Count(e => e.Risk == 2)} with wide reach)", $"إضافات المتصفح ({er.Count}، منها {_exts.Count(e => e.Risk == 2)} واسعة الصلاحية)"), eb,
                L("“High” means the extension can read and change every site and also holds a sensitive permission. That is what a password stealer needs — and also what an ad blocker needs. Remove the ones you do not recognise.", "«عالٍ» يعني أن الإضافة تقرأ وتغيّر كل المواقع ولها صلاحية حساسة أيضاً. هذا ما يحتاجه سارق كلمات المرور، وما يحتاجه مانع الإعلانات كذلك. احذف ما لا تعرفه.")));

            // ---- devices on the network
            _devices ??= Extras.LanDevices();
            var dr = _devices.Select(d => new DevRow { Ip = d.Ip, Mac = d.Mac, Note = d.Gateway ? L("router / gateway", "الموجّه (الراوتر)") : d.IsNew ? L("NEW — not seen before", "جديد — لم يُرَ من قبل") : "" }).ToList();
            var dg = Table(dr, (L("Address", "العنوان"), "Ip", 170, true), ("MAC", "Mac", 190, true), (L("Note", "ملاحظة"), "Note", -1, false));
            dg.MaxHeight = 300;
            var db = new StackPanel();
            db.Children.Add(dr.Count == 0 ? Empty(L("No neighbours in the ARP cache.", "لا جيران في ذاكرة ARP.")) : dg);
            var dbar = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
            dbar.Children.Add(Button(L("Refresh", "تحديث"), () => { _devices = Extras.LanDevices(); Render(); }, Kind.Ghost, 12.5));
            db.Children.Add(dbar);
            Add(Section(L($"Devices on your network ({dr.Count})", $"الأجهزة على شبكتك ({dr.Count})"), db,
                L("Devices this PC has exchanged packets with (the ARP cache), not a full scan. A device that appears for the first time is logged as an event.", "الأجهزة التي تبادل معها هذا الحاسوب حزماً (ذاكرة ARP)، وليس مسحاً كاملاً. الجهاز الذي يظهر لأول مرة يُسجَّل كحدث.")));

            // ---- tools
            var tb = new WrapPanel();
            tb.Children.Add(Button(L("Shred a file…", "إتلاف ملف نهائياً…"), () =>
            {
                var d = new Microsoft.Win32.OpenFileDialog { Title = "Sour" };
                if (d.ShowDialog(this) != true) return;
                if (MessageBox.Show(L("Overwrite this file with random data and delete it? It cannot be brought back.\n\n", "الكتابة فوق هذا الملف ببيانات عشوائية ثم حذفه؟ لا يمكن استرجاعه.\n\n") + d.FileName, "Sour", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                var r = Extras.Shred(d.FileName);
                Note(r.ok ? L("The file was overwritten and deleted.", "كُتب فوق الملف وحُذف.") : r.error);
            }, Kind.Danger, 12.5));
            Add(Section(L("Tools", "أدوات"), tb, L("Shredding overwrites the file once with random data. On SSDs some old blocks may survive wear-levelling.", "الإتلاف يكتب فوق الملف مرة واحدة ببيانات عشوائية. على أقراص SSD قد تبقى بعض الكتل القديمة.")));
        }

        // ------------------------------------------------------------------ 07 events
        string _evFilter = "all";

        void PageEvents()
        {
            var all = Log.Snapshot();
            IEnumerable<SecEvent> q = all.AsEnumerable().Reverse();
            if (_evFilter == "important") q = q.Where(e => e.Level >= Severity.Medium);
            else if (_evFilter != "all") q = q.Where(e => e.Kind.ToString() == _evFilter);
            var rows = q.Take(800).Select(e => new EventRow(e)).ToList();
            var filters = new List<(string, string)> { ("all", L("All", "الكل")), ("important", L("Important", "المهمة")) };
            foreach (EventKind k in Enum.GetValues(typeof(EventKind))) filters.Add((k.ToString(), KindText(k)));
            var body = new StackPanel();
            body.Children.Add(Segments(filters, _evFilter, k => { _evFilter = k; Render(); }));
            var grid = Table(rows, (L("Time", "الوقت"), "Time", 78, true), (L("Level", "المستوى"), "Level", 84, false), (L("Area", "المجال"), "Kind", 130, false), (L("What happened", "ما الذي حدث"), "Title", 420, false), (L("Evidence", "الدليل"), "Detail", -1, true));
            grid.MaxHeight = 430;
            var detail = MonoText("", 11.5); detail.Margin = new Thickness(0, 10, 0, 0);
            grid.SelectionChanged += (_, _) => { if (grid.SelectedItem is EventRow x) detail.Text = $"{x.E.Time:yyyy-MM-dd HH:mm:ss}  [{x.E.Code}]  {x.E.Title}\n{x.E.Detail}"; };
            body.Children.Add(rows.Count == 0 ? Empty(L("No events for this filter.", "لا أحداث لهذا الفلتر.")) : grid);
            body.Children.Add(detail);
            var bar = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
            bar.Children.Add(Button(L("Save as text…", "حفظ كنص…"), () =>
            {
                var d = new Microsoft.Win32.SaveFileDialog { FileName = "sour-events.txt", Filter = "Text|*.txt" };
                if (d.ShowDialog(this) != true) return;
                File.WriteAllLines(d.FileName, all.Select(e => $"{e.Time:yyyy-MM-dd HH:mm:ss}\t{e.Level}\t{e.Kind}\t{e.Code}\t{e.TitleEn}\t{(e.Detail ?? "").Replace("\n", " | ")}"), new UTF8Encoding(true));
            }, Kind.Ghost, 12.5));
            bar.Children.Add(Button(L("Clear the log", "مسح السجل"), () => { Log.Clear(); Render(); }, Kind.Ghost, 12.5));
            body.Children.Add(bar);
            Add(Section(L($"Events ({rows.Count} of {all.Count})", $"الأحداث ({rows.Count} من {all.Count})"), body));
        }

        // ------------------------------------------------------------------ 08 settings
        void PageSettings()
        {
            var s = Settings.Current;
            var gen = new StackPanel();
            gen.Children.Add(Label(L("Language", "اللغة")));
            gen.Children.Add(Segments(new List<(string, string)> { ("ar", "العربية"), ("en", "English") }, s.Language, k => I18n.Set(k)));
            gen.Children.Add(new Border { Height = 8 });
            bool auto = false; try { auto = Services.AutoStartEnabled(); } catch { }
            gen.Children.Add(Toggle(L("Start with Windows (as administrator)", "التشغيل مع ويندوز (بصلاحية مدير)"), L("Creates a scheduled task so Sour starts minimised at sign-in and can manage the firewall.", "ينشئ مهمة مجدولة ليبدأ سور مصغَّراً عند الدخول ويتمكن من إدارة الجدار الناري."), auto, v =>
            {
                if (!Admin) { Note(L("This needs an elevated Sour.", "يتطلب ذلك تشغيل سور كمدير.")); Render(); return; }
                if (!Services.SetAutoStart(v)) Note(L("The scheduled task could not be changed.", "تعذّر تغيير المهمة المجدولة."));
            }));
            gen.Children.Add(Toggle(L("Desktop notifications", "إشعارات سطح المكتب"), L("A tray balloon for high and critical events.", "إشعار من شريط المهام للأحداث العالية والحرجة."), s.Notifications, v => { s.Notifications = v; Settings.Save(); }));
            gen.Children.Add(Toggle(L("“Scan with Sour” in the Explorer right-click menu", "«فحص بواسطة سور» في قائمة الزر الأيمن"), L("Adds an entry for files and folders (this user only).", "يضيف خياراً للملفات والمجلدات (لهذا المستخدم فقط)."), s.ExplorerMenu, v =>
            {
                try { Services.SetExplorerMenu(v); s.ExplorerMenu = v; Settings.Save(); } catch (Exception ex) { Note(ex.Message); }
            }));
            gen.Children.Add(Label(L("Daily quick scan", "فحص سريع يومي")));
            gen.Children.Add(Segments(new List<(string, string)> { ("-1", L("Off", "متوقف")), ("9", "09:00"), ("13", "13:00"), ("20", "20:00"), ("2", "02:00") }, s.ScheduledScanHour.ToString(), k => { s.ScheduledScanHour = int.Parse(k); Settings.Save(); Render(); }));
            Add(Section(L("General", "عام"), gen));

            var eng = new StackPanel();
            void Opt(string en, string ar, string hen, string har, Func<bool> get, Action<bool> set) => eng.Children.Add(Toggle(L(en, ar), L(hen, har), get(), v => { set(v); Settings.Save(); }));
            Opt("AI model", "نموذج الذكاء الاصطناعي", "Score Windows programs with the trained model.", "تقييم برامج ويندوز بالنموذج المدرَّب.", () => s.AvUseMl, v => s.AvUseMl = v);
            Opt("AMSI second opinion", "رأي ثانٍ من AMSI", "Ask the antimalware provider registered in Windows (normally Microsoft Defender) about scripts and unsigned files. Stays on this PC.", "سؤال مزوّد الحماية المسجَّل في ويندوز (غالباً Microsoft Defender) عن السكربتات والملفات غير الموقَّعة. يبقى على هذا الجهاز.", () => s.AvUseAmsi, v => s.AvUseAmsi = v);
            Opt("Look inside archives", "الفحص داخل الأرشيفات", "ZIP, JAR and Office files, two levels deep.", "ملفات ZIP و JAR وأوفيس حتى مستويين.", () => s.AvScanArchives, v => s.AvScanArchives = v);
            eng.Children.Add(Label(L("Largest file to analyse in full (MB)", "أكبر ملف يُحلَّل كاملاً (ميغابايت)")));
            eng.Children.Add(Segments(new[] { 64, 128, 256, 512 }.Select(v => (v.ToString(), v.ToString())).ToList(), s.AvMaxFileMb.ToString(), k => { s.AvMaxFileMb = int.Parse(k); Settings.Save(); Render(); }));
            Add(Section(L("Detection engines", "محركات الكشف"), eng));

            // exclusions
            var exb = new StackPanel();
            var lb = new ListBox { ItemsSource = s.AvExclusions.ToList(), FontFamily = Mono, FontSize = 11.5, BorderBrush = Ink, BorderThickness = new Thickness(2), Background = White, MaxHeight = 170, MinHeight = 44, FlowDirection = FlowDirection.LeftToRight };
            exb.Children.Add(lb);
            var eb = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
            eb.Children.Add(Button(L("Exclude a folder…", "استثناء مجلد…"), () => { var d = new Microsoft.Win32.OpenFolderDialog(); if (d.ShowDialog(this) == true && !s.AvExclusions.Contains(d.FolderName)) { s.AvExclusions.Add(d.FolderName); Settings.Save(); Render(); } }, Kind.Ghost, 12.5));
            eb.Children.Add(Button(L("Exclude a file…", "استثناء ملف…"), () => { var d = new Microsoft.Win32.OpenFileDialog(); if (d.ShowDialog(this) == true && !s.AvExclusions.Contains(d.FileName)) { s.AvExclusions.Add(d.FileName); Settings.Save(); Render(); } }, Kind.Ghost, 12.5));
            eb.Children.Add(Button(L("Remove selected", "حذف المحدد"), () => { if (lb.SelectedItem is string x) { s.AvExclusions.Remove(x); Settings.Save(); Render(); } }, Kind.Ghost, 12.5));
            exb.Children.Add(eb);
            Add(Section(L($"Exclusions ({s.AvExclusions.Count})", $"الاستثناءات ({s.AvExclusions.Count})"), exb, L("Files and folders the antivirus skips.", "ملفات ومجلدات يتجاوزها مكافح الفيروسات.")));

            // feeds
            var fd = new StackPanel();
            var status = MonoText(L($"blocked hashes: {HashDb.Set.Count:N0} · feed addresses: {RuleStore.Current.BlockedIps.Count(i => i.Note == "feed:feodo")}", $"البصمات المحظورة: {HashDb.Set.Count:N0} · عناوين القوائم: {RuleStore.Current.BlockedIps.Count(i => i.Note == "feed:feodo")}"), 11.5, Steel);
            var fbar = new WrapPanel();
            fbar.Children.Add(Button(L("Update botnet address feed now", "تحديث قائمة عناوين البوت نت الآن"), async () =>
            {
                status.Text = L("downloading…", "جارٍ التنزيل…");
                string r = await Services.UpdateFeeds();
                status.Text = r;
            }, Kind.Primary, 12.5));
            fbar.Children.Add(Button(L("Import a SHA-256 list…", "استيراد قائمة بصمات SHA-256…"), () =>
            {
                var d = new Microsoft.Win32.OpenFileDialog { Filter = "Text|*.txt;*.csv|All files|*.*", Title = "Sour" };
                if (d.ShowDialog(this) != true) return;
                int n = Services.ImportHashes(d.FileName);
                Note(L($"{n} hashes imported.", $"استُوردت {n} بصمة.")); Render();
            }, Kind.Ghost, 12.5));
            var hin = Input("", 420, "SHA-256");
            fbar.Children.Add(hin);
            fbar.Children.Add(Button(L("Block this SHA-256", "حظر هذه البصمة"), () =>
            {
                string h = hin.Text.Trim();
                if (h.Length != 64 || !h.All(Uri.IsHexDigit)) { Note(L("A SHA-256 is 64 hexadecimal characters.", "بصمة SHA-256 مكوّنة من 64 حرفاً ست عشرياً.")); return; }
                HashDb.AddUser(h, "user"); Render();
            }, Kind.Ghost, 12.5));
            fd.Children.Add(fbar); fd.Children.Add(status);
            fd.Children.Add(Text(L("The address feed is fetched only when you press the button: botnet command-server addresses from abuse.ch Feodo Tracker. Nothing about this PC is sent. Hash lists (one SHA-256 per line) can be imported from any file you trust.",
                "لا تُجلب قائمة العناوين إلا عند ضغط الزر: عناوين خوادم التحكم بشبكات البوت من abuse.ch Feodo Tracker. لا يُرسل أي شيء عن هذا الجهاز. ويمكن استيراد قوائم البصمات (بصمة SHA-256 في كل سطر) من أي ملف تثق به."), 12.5, Steel));
            Add(Section(L("Threat feeds and block lists", "قوائم التهديدات والحظر"), fd));

            // about
            var ab = new StackPanel();
            void P(string en, string ar) { var t = Text(L(en, ar), 13.2, Ink); t.Margin = new Thickness(0, 0, 0, 8); ab.Children.Add(t); }
            P("Sour (Arabic for “wall”) is a firewall and antivirus that runs completely on this PC.", "سور جدار ناري ومكافح فيروسات يعمل كلياً على هذا الجهاز.");
            P("Firewall — Sour registers its own provider and sublayer in the Windows Filtering Platform and installs permit/block filters at the connect and accept layers. That is the mechanism Windows Firewall itself uses; a block in Sour's sublayer cannot be overridden by another firewall's permit.",
              "الجدار الناري — يسجّل سور مزوّداً وطبقة فرعية خاصين به في منصّة التصفية في ويندوز (WFP) ويثبّت مرشّحات سماح/حظر عند طبقتي الاتصال والقبول. وهي الآلية نفسها التي يستخدمها جدار ويندوز؛ والحظر في طبقة سور لا يلغيه سماح من جدار آخر.");
            P("Antivirus — every file passes a hash block list, 40+ signature rules, structural heuristics, a gradient-boosted model trained on EMBER2024, and (optionally) AMSI. Each point of the score is listed with its reason.",
              "مكافح الفيروسات — يمرّ كل ملف على قائمة بصمات، وأكثر من 40 قاعدة توقيع، واستدلالات بنيوية، ونموذج أشجار معزَّزة مدرَّب على EMBER2024، و(اختيارياً) AMSI. كل نقطة في الدرجة مذكورة بسببها.");
            P("Limits you should know — Sour has no kernel driver. It therefore examines a file right after it is written and a program right after it starts, not before; it cannot inspect encrypted traffic contents; and a program running as administrator could remove its filters (Sour checks for that and restores them). Keep Microsoft Defender enabled: the two work side by side.",
              "حدود يجب معرفتها — لا يملك سور مشغّل نواة. لذا يفحص الملف فور كتابته والبرنامج فور تشغيله لا قبل ذلك؛ ولا يستطيع فحص محتوى المرور المشفَّر؛ وبرنامج يعمل بصلاحية مدير قد يزيل مرشّحاته (سور يتحقق من ذلك ويعيدها). أبقِ Microsoft Defender مفعّلاً: الاثنان يعملان جنباً إلى جنب.");
            ab.Children.Add(MonoText(L("Data folder: ", "مجلد البيانات: ") + Paths.Root, 11.5, Steel));
            ab.Children.Add(MonoText("Sour 1.0 · Dr. Mohammed Tawfik · Ajloun National University", 11.5, Steel));
            var abb = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
            abb.Children.Add(Button(L("Open data folder", "فتح مجلد البيانات"), () => System.Diagnostics.Process.Start("explorer.exe", Paths.Root), Kind.Ghost, 12.5));
            ab.Children.Add(abb);
            Add(Section(L("How Sour works", "كيف يعمل سور"), ab));
        }
    }
}
