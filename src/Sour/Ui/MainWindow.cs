using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using Sour.Av;
using Sour.Core;
using Sour.Fw;
using static Sour.Ui.T;

namespace Sour.Ui
{
    public sealed partial class MainWindow : Window
    {
        public static readonly string[] PageIds = { "overview", "firewall", "connections", "antivirus", "quarantine", "ai", "audit", "events", "settings" };
        string _page = "overview";
        readonly Grid _root = new Grid();
        StackPanel _body; ScrollViewer _scroll;
        Action _tick;
        readonly DispatcherTimer _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        public bool Admin = Util.IsAdmin();

        public MainWindow()
        {
            Title = "Sour — سور"; Width = 1320; Height = 860; MinWidth = 1080; MinHeight = 680;
            Background = Stone; FontFamily = BodyFont; UseLayoutRounding = true; SnapsToDevicePixels = true;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            TextOptions.SetTextFormattingMode(this, TextFormattingMode.Display);
            Content = _root;
            I18n.Changed += () => Dispatcher.Invoke(Render);
            _timer.Tick += (_, _) => { try { _tick?.Invoke(); } catch { } };
            _timer.Start();
            Guard.Instance.Detected += _ => Dispatcher.BeginInvoke(new Action(() => { if (_page == "antivirus" || _page == "overview") Render(); }));
            BlockWatcher.Instance.Changed += () => Dispatcher.BeginInvoke(new Action(() => { if (_page == "firewall") Render(); }));
            Quarantine.Changed += () => Dispatcher.BeginInvoke(new Action(() => { if (_page == "quarantine") Render(); }));
            Render();
        }

        public void Go(string page) { _page = page; Render(); _scroll?.ScrollToTop(); }

        public double BodyHeight => _body == null ? 0 : _body.DesiredSize.Height;     // DesiredSize already includes the margin

        public int CountTexts()
        {
            int n = 0;
            void Walk(DependencyObject d)
            {
                if (d is TextBlock tb && !string.IsNullOrWhiteSpace(tb.Text)) n++;
                for (int i = 0; i < VisualTreeHelper.GetChildrenCount(d); i++) Walk(VisualTreeHelper.GetChild(d, i));
            }
            Walk(_root);
            return n;
        }

        static string PageTitle(string id) => id switch
        {
            "overview" => L("Overview", "النظرة العامة"), "firewall" => L("Firewall", "الجدار الناري"), "connections" => L("Live connections", "الاتصالات الحيّة"),
            "antivirus" => L("Antivirus", "مكافح الفيروسات"), "quarantine" => L("Quarantine", "الحجر الصحي"), "ai" => L("AI centre", "مركز الذكاء الاصطناعي"),
            "events" => L("Event log", "سجل الأحداث"), "audit" => L("Security audit", "تدقيق الأمان"), _ => L("Settings", "الإعدادات"),
        };
        static string PageHint(string id) => id switch
        {
            "overview" => L("What is protected right now, and what happened recently.", "ما المحمي الآن، وما الذي حدث مؤخراً."),
            "firewall" => L("Decide which programs may use the network. Enforced by the Windows Filtering Platform.", "حدّد أي البرامج يُسمح لها باستخدام الشبكة. يُفرض عبر منصّة التصفية في ويندوز."),
            "connections" => L("Every open connection with its owning program and an AI risk score.", "كل اتصال مفتوح مع البرنامج المالك له ودرجة خطورة من الذكاء الاصطناعي."),
            "antivirus" => L("Signatures, heuristics and a machine-learning model, each verdict explained.", "تواقيع واستدلالات ونموذج تعلّم آلي، وكل حكم مشروح."),
            "quarantine" => L("Neutralised files. Restore or delete them permanently.", "ملفات مُعطَّلة. استعدها أو احذفها نهائياً."),
            "ai" => L("The model, how well it performs, and why it decides what it decides.", "النموذج، ومدى دقته، ولماذا يقرّر ما يقرّره."),
            "events" => L("Everything Sour saw and did.", "كل ما رآه سور وما فعله."),
            _ => L("Language, exclusions, feeds and how Sour works.", "اللغة، الاستثناءات، قوائم التهديدات، وكيف يعمل سور."),
        };

        // ------------------------------------------------------------------ shell
        public void Render()
        {
            _tick = null;
            FlowDirection = I18n.IsArabic ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;
            _root.FlowDirection = FlowDirection;
            _root.Children.Clear(); _root.ColumnDefinitions.Clear();
            _root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(244) });
            _root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            _root.Children.Add(Rail());

            var right = new DockPanel();
            Grid.SetColumn(right, 1);
            var header = Header();
            DockPanel.SetDock(header, Dock.Top); right.Children.Add(header);
            var status = StatusBar(); DockPanel.SetDock(status, Dock.Bottom); right.Children.Add(status);
            _body = new StackPanel { Margin = new Thickness(30, 14, 24, 26) };
            _scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _body };
            right.Children.Add(_scroll);
            _root.Children.Add(right);

            try
            {
                switch (_page)
                {
                    case "overview": PageOverview(); break;
                    case "firewall": PageFirewall(); break;
                    case "connections": PageConnections(); break;
                    case "antivirus": PageAntivirus(); break;
                    case "quarantine": PageQuarantine(); break;
                    case "ai": PageAi(); break;
                    case "events": PageEvents(); break;
                    case "audit": PageAudit(); break;
                    default: PageSettings(); break;
                }
            }
            catch (Exception ex) { _body.Children.Add(Card(MonoText(ex.ToString(), 11, Red))); }
        }

        void Add(UIElement e) { if (e is FrameworkElement fe && fe.Margin == default) fe.Margin = new Thickness(0, 0, 0, 18); else if (e is FrameworkElement f2) f2.Margin = new Thickness(f2.Margin.Left, f2.Margin.Top, f2.Margin.Right, f2.Margin.Bottom + 12); _body.Children.Add(e); }

        /// <summary>The wall mark: three courses of offset bricks.</summary>
        static FrameworkElement WallMark(double unit = 9)
        {
            var c = new Canvas { Width = unit * 6 + 4, Height = unit * 3 + 4, FlowDirection = FlowDirection.LeftToRight };
            for (int row = 0; row < 3; row++)
            {
                double off = row % 2 == 0 ? 0 : -unit;
                for (int i = 0; i < 4; i++)
                {
                    double x = off + i * (unit * 2 + 2);
                    if (x >= unit * 6 + 2) continue;
                    double w = Math.Min(unit * 2, unit * 6 + 4 - Math.Max(x, 0)) - (x < 0 ? 0 : 0);
                    double left = Math.Max(x, 0); if (x < 0) w = unit * 2 + x;
                    if (w <= 1) continue;
                    var r = new Rectangle { Width = w, Height = unit, Fill = row == 1 && i == 2 ? White : Brick };
                    Canvas.SetLeft(r, left); Canvas.SetTop(r, row * (unit + 2));
                    c.Children.Add(r);
                }
            }
            return c;
        }

        FrameworkElement Rail()
        {
            var dock = new DockPanel { Background = Ink };
            var top = new StackPanel { Margin = new Thickness(22, 26, 22, 18) };
            top.Children.Add(WallMark());
            top.Children.Add(new TextBlock { Text = L("SOUR", "سور"), FontFamily = Head, FontWeight = FontWeights.Bold, FontSize = 44, Foreground = White, Margin = new Thickness(0, 10, 0, 0), LineHeight = 46, LineStackingStrategy = LineStackingStrategy.BlockLineHeight });
            top.Children.Add(new TextBlock { Text = L("AI FIREWALL + ANTIVIRUS", "جدار ناري ومكافح فيروسات بالذكاء الاصطناعي"), FontFamily = LabelFont, FontSize = I18n.IsArabic ? 12 : 10.5, Foreground = Brick, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) });
            DockPanel.SetDock(top, Dock.Top); dock.Children.Add(top);

            var bottom = new StackPanel { Margin = new Thickness(22, 10, 22, 20) };
            bottom.Children.Add(new Border
            {
                Background = Admin ? Moss : Amber, Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 0, 0, 10),
                Child = new TextBlock { Text = Admin ? L("ADMINISTRATOR", "صلاحية مدير") : L("STANDARD USER", "مستخدم عادي"), FontFamily = LabelFont, FontSize = I18n.IsArabic ? 12.5 : 11, Foreground = Admin ? White : Ink, FontWeight = FontWeights.Bold },
            });
            var lang = new Border { BorderBrush = White, BorderThickness = new Thickness(2), Padding = new Thickness(10, 6, 10, 6), Cursor = Cursors.Hand, Background = Ink, Tag = "lang",
                Child = new TextBlock { Text = I18n.IsArabic ? "English" : "العربية", FontFamily = BodyFont, FontSize = 13, Foreground = White, FontWeight = FontWeights.SemiBold, TextAlignment = TextAlignment.Center } };
            lang.MouseLeftButtonUp += (_, _) => I18n.Toggle();
            bottom.Children.Add(lang);
            bottom.Children.Add(new TextBlock { Text = "v1.0 · " + L("local, no cloud", "محلي بلا سحابة"), FontFamily = LabelFont, FontSize = 10.5, Foreground = Steel, Margin = new Thickness(0, 10, 0, 0) });
            DockPanel.SetDock(bottom, Dock.Bottom); dock.Children.Add(bottom);

            var nav = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
            int n = 0;
            int pending; lock (Guard.Instance.Pending) pending = Guard.Instance.Pending.Count(d => d.State == "pending");
            int fwPending; lock (BlockWatcher.Instance.Pending) fwPending = BlockWatcher.Instance.Pending.Count;
            foreach (string id in PageIds)
            {
                n++;
                bool on = id == _page;
                var row = new DockPanel { Background = on ? Brick : Ink, Cursor = Cursors.Hand, Tag = "nav:" + id };
                var num = new TextBlock { Text = n.ToString("00"), FontFamily = Mono, FontSize = 11, Foreground = on ? Ink : Steel, Margin = new Thickness(22, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center, FlowDirection = FlowDirection.LeftToRight };
                DockPanel.SetDock(num, Dock.Left); row.Children.Add(num);
                int badge = id == "antivirus" ? pending : id == "firewall" ? fwPending : id == "quarantine" ? Quarantine.Items.Count : 0;
                if (badge > 0)
                {
                    var bd = new Border { Background = on ? Ink : Brick, Padding = new Thickness(6, 1, 6, 2), Margin = new Thickness(0, 0, 18, 0), VerticalAlignment = VerticalAlignment.Center, Child = new TextBlock { Text = badge.ToString(), FontFamily = Mono, FontSize = 10.5, Foreground = White, FontWeight = FontWeights.Bold } };
                    DockPanel.SetDock(bd, Dock.Right); row.Children.Add(bd);
                }
                row.Children.Add(new TextBlock { Text = PageTitle(id), FontFamily = BodyFont, FontSize = 14.5, FontWeight = on ? FontWeights.Bold : FontWeights.Normal, Foreground = White, Margin = new Thickness(0, 11, 0, 11) });
                string target = id;
                row.MouseLeftButtonUp += (_, _) => Go(target);
                if (!on) { row.MouseEnter += (_, _) => row.Background = Ink2; row.MouseLeave += (_, _) => row.Background = Ink; }
                nav.Children.Add(row);
            }
            dock.Children.Add(nav);
            return dock;
        }

        FrameworkElement Header()
        {
            var dp = new DockPanel { Margin = new Thickness(30, 16, 24, 0) };
            dp.Children.Add(new TextBlock { Text = PageTitle(_page), FontFamily = Head, FontWeight = FontWeights.Bold, FontSize = 26, Foreground = Ink });
            return dp;
        }

        /// <summary>Bottom status line, as in a real system tool: plain facts, no decoration.</summary>
        FrameworkElement StatusBar()
        {
            var s = Settings.Current; var g = Guard.Instance;
            string On(bool b) => b ? L("on", "يعمل") : L("off", "متوقف");
            var parts = new[]
            {
                L("firewall: ", "الجدار: ") + ModeName(s.FirewallMode),
                L("file guard: ", "حارس الملفات: ") + On(g.FileGuardOn),
                L("process guard: ", "حارس العمليات: ") + On(g.ProcessGuardOn),
                L("ransomware shield: ", "درع الفدية: ") + On(g.RansomShieldOn),
                L("AI model: ", "نموذج الذكاء: ") + (MlModel.Instance.Loaded ? L("loaded", "محمَّل") : L("missing", "مفقود")),
                Admin ? L("administrator", "مدير") : L("standard user", "مستخدم عادي"),
            };
            var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(30, 0, 24, 0) };
            for (int i = 0; i < parts.Length; i++)
            {
                if (i > 0) sp.Children.Add(new Border { Width = 1, Background = Hair, Margin = new Thickness(12, 5, 12, 5) });
                sp.Children.Add(new TextBlock { Text = parts[i], FontFamily = LabelFont, FontSize = 11.5, Foreground = Ink, VerticalAlignment = VerticalAlignment.Center });
            }
            return new Border { Background = Paper, BorderBrush = Ink, BorderThickness = new Thickness(0, 1, 0, 0), Height = 28, Child = sp };
        }

        public static string ModeName(FwMode m) => m switch
        {
            FwMode.Off => L("Off", "متوقف"), FwMode.Monitor => L("Monitor", "مراقبة"), FwMode.Blocklist => L("Block list", "قائمة الحظر"),
            FwMode.Whitelist => L("Whitelist", "القائمة البيضاء"), _ => L("Lockdown", "إغلاق تام"),
        };

        FrameworkElement AdminBanner(string what)
        {
            var dp = new DockPanel();
            var btn = Button(L("Restart as administrator", "إعادة التشغيل كمدير"), () => { if (Util.RestartElevated()) Application.Current.Shutdown(); }, Kind.Dark);
            DockPanel.SetDock(btn, Dock.Right); dp.Children.Add(btn);
            var sp = new StackPanel();
            sp.Children.Add(Text(L("Administrator rights needed", "تلزم صلاحية المدير"), 15, Ink, FontWeights.Bold));
            sp.Children.Add(Text(what, 12.5, Ink));
            dp.Children.Add(sp);
            return Card(dp, Amber, 14, new SolidColorBrush(Color.FromRgb(0xFB, 0xEF, 0xC8)));
        }

        // ------------------------------------------------------------------ 01 overview
        // The wall: one brick per program that is on the network right now.
        string _wallSig = "";

        void BuildWall(WrapPanel wall, TextBlock legend)
        {
            var groups = Services.Conn.Current.Where(c => !c.IsListener && c.Remote != null && !System.Net.IPAddress.IsLoopback(c.Remote) && c.Pid != 0)
                .GroupBy(c => c.ProcessPath ?? "", StringComparer.OrdinalIgnoreCase)
                .Select(g => new { Path = g.Key, Name = g.First().ProcessName, Count = g.Count(), Risk = g.Max(c => c.Risk), Rule = RuleStore.Current.Find(g.Key) })
                .OrderByDescending(g => g.Count).ThenBy(g => g.Name).ToList();
            string sig = string.Join("|", groups.Select(g => g.Path + ":" + g.Count + ":" + (g.Rule == null ? "-" : g.Rule.Action.ToString()) + ":" + (g.Risk >= 30)));
            if (sig == _wallSig && wall.Children.Count > 0) return;
            _wallSig = sig;
            wall.Children.Clear();
            int allowed = 0, blocked = 0, open = 0;
            foreach (var g in groups)
            {
                bool allow = g.Rule != null && g.Rule.Enabled && g.Rule.Action == RuleAction.Allow && !g.Rule.HashChanged;
                bool block = g.Rule != null && g.Rule.Enabled && g.Rule.Action == RuleAction.Block;
                if (allow) allowed++; else if (block) blocked++; else open++;
                Brush bg = allow ? Moss : block ? Red : Stone, fg = allow || block ? White : Ink;
                var name = new TextBlock { Text = g.Name, FontFamily = BodyFont, FontWeight = FontWeights.SemiBold, FontSize = 12.5, Foreground = fg, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
                var cnt = new TextBlock { Text = g.Count.ToString(), FontFamily = Mono, FontSize = 11, Foreground = fg, Opacity = 0.75, Margin = new Thickness(8, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                var dp = new DockPanel { FlowDirection = FlowDirection.LeftToRight };
                DockPanel.SetDock(cnt, Dock.Right); dp.Children.Add(cnt); dp.Children.Add(name);
                var brick = new Border
                {
                    Width = Math.Min(250, 96 + Math.Min(g.Count, 22) * 7), Height = 40, Margin = new Thickness(0, 0, 4, 4), Padding = new Thickness(10, 0, 10, 0),
                    Background = bg, BorderBrush = g.Risk >= 30 ? Amber : Ink, BorderThickness = new Thickness(g.Risk >= 30 ? 3 : 1), Cursor = Cursors.Hand, Child = dp,
                    ToolTip = g.Path + (g.Risk >= 30 ? " — " + L("AI risk ", "خطورة الذكاء ") + g.Risk.ToString("0") : ""), Tag = "brick",
                };
                string path = g.Path; string ruleId = g.Rule?.Id;
                var menu = new ContextMenu { FlowDirection = FlowDirection };
                void Item(string text, Action act) { var mi = new MenuItem { Header = text }; mi.Click += (_, _) => { act(); _wallSig = ""; Render(); }; menu.Items.Add(mi); }
                if (File.Exists(path))
                {
                    Item(L("Allow", "سماح"), () => FirewallEngine.SetRule(path, RuleAction.Allow));
                    Item(L("Block", "حظر"), () => FirewallEngine.SetRule(path, RuleAction.Block));
                    if (ruleId != null) Item(L("Remove rule", "حذف القاعدة"), () => FirewallEngine.RemoveRule(ruleId));
                    Item(L("Scan this program", "فحص هذا البرنامج"), () => ShowResult(Scanner.Instance.ScanFile(path, false)));
                }
                Item(L("Show its connections", "عرض اتصالاته"), () => Go("connections"));
                brick.ContextMenu = menu;
                brick.MouseLeftButtonUp += (_, _) => { menu.PlacementTarget = brick; menu.IsOpen = true; };
                wall.Children.Add(brick);
            }
            legend.Text = L($"{groups.Count} programs online — {allowed} allowed, {blocked} blocked, {open} without a rule. Click a brick to decide. Amber frame = unusual traffic.",
                $"{groups.Count} برنامجاً متصلاً — {allowed} مسموح، {blocked} محظور، {open} بلا قاعدة. اضغط على الحجر لتقرّر. الإطار الأصفر = مرور غير معتاد.");
        }

        void PageOverview()
        {
            var s = Settings.Current;
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(318) });

            // ---- the wall
            var wall = new WrapPanel { FlowDirection = FlowDirection.LeftToRight };
            var legend = Text("", 12, Steel); legend.Margin = new Thickness(0, 8, 0, 0);
            _wallSig = "";
            BuildWall(wall, legend);
            var wb = new StackPanel { Margin = new Thickness(0, 0, 26, 0) };
            var key = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
            void Key(Brush b, string t) { key.Children.Add(new Border { Width = 14, Height = 14, Background = b, BorderBrush = Ink, BorderThickness = new Thickness(1), Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center }); key.Children.Add(Text(t, 12, Ink)); key.Children.Add(new Border { Width = 16 }); }
            Key(Moss, L("allowed", "مسموح")); Key(Red, L("blocked", "محظور")); Key(Stone, L("no rule yet", "بلا قاعدة"));
            wb.Children.Add(key);
            if (wall.Children.Count == 0) wb.Children.Add(Empty(L("No program is using the network right now.", "لا يوجد برنامج يستخدم الشبكة الآن.")));
            wb.Children.Add(wall);
            wb.Children.Add(legend);
            grid.Children.Add(Section(L("The wall — who is on the network now", "السور — من على الشبكة الآن"), wb));

            // ---- switches
            var sw = new StackPanel();
            void Sw(string en, string ar, Func<bool> get, Action<bool> set) => sw.Children.Add(Toggle(L(en, ar), null, get(), v => { set(v); Settings.Save(); Guard.Instance.Sync(); Dispatcher.BeginInvoke(new Action(Render)); }));
            var fwRow = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };
            var fwBtn = Button(L("Change", "تغيير"), () => Go("firewall"), Kind.Ghost, 12); fwBtn.Margin = new Thickness(0);
            DockPanel.SetDock(fwBtn, Dock.Right); fwRow.Children.Add(fwBtn);
            fwRow.Children.Add(Text(L("Firewall: ", "الجدار الناري: ") + ModeName(s.FirewallMode), 13.5, Ink, FontWeights.SemiBold));
            sw.Children.Add(fwRow);
            Sw("File guard", "حارس الملفات", () => s.AvRealtime, v => s.AvRealtime = v);
            Sw("Process guard", "حارس العمليات", () => s.AvProcessWatch, v => s.AvProcessWatch = v);
            Sw("Ransomware shield", "درع الفدية", () => s.AvRansomShield, v => s.AvRansomShield = v);
            Sw("Network AI", "ذكاء الشبكة", () => s.NetAi, v => s.NetAi = v);
            Sw("USB guard", "حارس USB", () => s.AvUsbScan, v => s.AvUsbScan = v);
            Sw("Startup watch", "مراقبة بدء التشغيل", () => s.AvPersistenceWatch, v => s.AvPersistenceWatch = v);
            var acts = new WrapPanel();
            acts.Children.Add(Button(L("Quick scan", "فحص سريع"), () => { Go("antivirus"); StartScan(Scanner.QuickScanRoots().ToList(), false); }, Kind.Primary, 13));
            if (!Admin) acts.Children.Add(Button(L("Run as administrator", "تشغيل كمدير"), () => { if (Util.RestartElevated()) Application.Current.Shutdown(); }, Kind.Ghost, 13));
            sw.Children.Add(acts);
            var right = Section(L("Protection", "الحماية"), sw);
            Grid.SetColumn(right, 1); grid.Children.Add(right);
            Add(grid);

            // ---- counters as plain ruled rows
            var live = FirewallEngine.LiveState();
            var m = MlModel.Instance;
            var c1 = new StackPanel { Margin = new Thickness(0, 0, 26, 0) }; var c2 = new StackPanel { Margin = new Thickness(0, 0, 26, 0) }; var c3 = new StackPanel();
            c1.Children.Add(Stat(L("Installed firewall filters", "مرشّحات الجدار المثبتة"), live.ok ? live.count.ToString() : L("needs admin", "يتطلب مديراً")));
            c1.Children.Add(Stat(L("Blocked connection attempts", "محاولات اتصال محجوبة"), BlockWatcher.Instance.BlockedTotal.ToString("N0")));
            c1.Children.Add(Stat(L("Unusual-traffic alerts", "إنذارات مرور غير معتاد"), Services.NetAlerts.ToString(), Services.NetAlerts > 0 ? Brick : Ink));
            c2.Children.Add(Stat(L("Files scanned this session", "ملفات مفحوصة هذه الجلسة"), Scanner.Instance.FilesScanned.ToString("N0")));
            c2.Children.Add(Stat(L("Threats flagged", "تهديدات مرصودة"), Scanner.Instance.Detections.ToString(), Scanner.Instance.Detections > 0 ? Red : Ink));
            c2.Children.Add(Stat(L("Files in quarantine", "ملفات في الحجر"), Quarantine.Items.Count.ToString()));
            c3.Children.Add(Stat(L("AI model accuracy (AUC, unseen weeks)", "دقة نموذج الذكاء (AUC، أسابيع لم يرها)"), m.Card != null ? m.Card.test_auc.ToString("0.0000") : "—"));
            c3.Children.Add(Stat(L("Signature rules", "قواعد التواقيع"), RuleEngine.Instance.Rules.Count.ToString()));
            c3.Children.Add(Stat(L("Programs with a learned profile", "برامج لها ملف سلوك"), Services.NetAi.Profiles.Count.ToString()));
            var cg = new UniformGrid { Columns = 3 }; cg.Children.Add(c1); cg.Children.Add(c2); cg.Children.Add(c3);
            Add(Section(L("Counters", "العدّادات"), cg));

            var ev = Log.Snapshot().AsEnumerable().Reverse().Take(12).Select(e => new EventRow(e)).ToList();
            Add(Section(L("Recent activity", "آخر النشاطات"), ev.Count == 0 ? Empty(L("Nothing yet.", "لا شيء بعد.")) : Table(ev,
                (L("Time", "الوقت"), "Time", 78, true), (L("Level", "المستوى"), "Level", 84, false), (L("Area", "المجال"), "Kind", 130, false), (L("What happened", "ما الذي حدث"), "Title", -1, false)),
                null, Button(L("Full log", "السجل الكامل"), () => Go("events"), Kind.Ghost, 12)));

            _tick = () => BuildWall(wall, legend);
        }

        public sealed class EventRow
        {
            public SecEvent E;
            public string Time { get; } public string Level { get; } public string Kind { get; } public string Title { get; } public string Detail { get; }
            public EventRow(SecEvent e) { E = e; Time = e.Time.ToString("HH:mm:ss"); Level = SeverityText(e.Level); Kind = KindText(e.Kind); Title = e.Title; Detail = (e.Detail ?? "").Replace("\n", "  ·  "); }
        }

        // ------------------------------------------------------------------ 02 firewall
        public sealed class RuleRow
        {
            public AppRule R;
            public string Name { get; } public string Action { get; } public string Path { get; } public string Publisher { get; } public string Source { get; } public string Pin { get; } public string Expires { get; }
            public RuleRow(AppRule r)
            {
                R = r; Name = r.Name; Path = r.Path;
                Action = !r.Enabled ? L("disabled", "معطّلة") : r.Action == RuleAction.Allow ? (r.AllowInbound ? L("ALLOW in+out", "سماح صادر+وارد") : L("ALLOW", "سماح")) : L("BLOCK", "حظر");
                Publisher = string.IsNullOrEmpty(r.Publisher) ? L("unsigned", "غير موقَّع") : r.Publisher;
                Source = r.Source switch { "autopilot" => L("auto-pilot", "الطيار الآلي"), "learn" => L("learned", "تعلّم"), _ => L("you", "أنت") };
                Pin = r.HashChanged ? L("CHANGED — suspended", "تغيّر — معلّقة") : string.IsNullOrEmpty(r.Hash) ? "—" : r.Hash.Substring(0, 12) + "…";
                Expires = r.Expires == null ? L("permanent", "دائمة") : r.Expires.Value.ToString("HH:mm");
            }
        }
        public sealed class IpRow { public IpRule R; public string Cidr { get; set; } public string Note { get; set; } }

        void ApplyFirewall()
        {
            if (!Admin) { MessageBox.Show(L("Run Sour as administrator to change the firewall.", "شغّل سور كمدير لتغيير الجدار الناري."), "Sour"); return; }
            var r = FirewallEngine.Apply();
            Services.SyncBlockWatcher();
            if (!r.Ok) MessageBox.Show(L("The policy could not be applied:\n", "تعذّر تطبيق السياسة:\n") + r.Error, "Sour", MessageBoxButton.OK, MessageBoxImage.Warning);
            Render();
        }

        void PageFirewall()
        {
            var s = Settings.Current; var store = RuleStore.Current;
            if (!Admin) Add(AdminBanner(L("You can prepare rules now; installing them into Windows needs an elevated Sour.", "يمكنك تجهيز القواعد الآن؛ تثبيتها في ويندوز يتطلب تشغيل سور بصلاحية مدير.")));

            // ---- mode
            var modeBody = new StackPanel();
            modeBody.Children.Add(Segments(new[] { FwMode.Off, FwMode.Monitor, FwMode.Blocklist, FwMode.Whitelist, FwMode.Lockdown }.Select(m => (m.ToString(), ModeName(m))).ToList(), s.FirewallMode.ToString(), k =>
            {
                s.FirewallMode = Enum.Parse<FwMode>(k); Settings.Save(); Render();
            }));
            string desc = s.FirewallMode switch
            {
                FwMode.Off => L("No Sour filters are installed. Windows Firewall keeps working as before.", "لا توجد مرشّحات من سور. جدار ويندوز يعمل كما كان."),
                FwMode.Monitor => L("Nothing is blocked. Sour only watches connections and learns each program's habits.", "لا يُحجب شيء. سور يراقب الاتصالات فقط ويتعلّم عادات كل برنامج."),
                FwMode.Blocklist => L("Everything is allowed except the programs and addresses you block.", "كل شيء مسموح عدا البرامج والعناوين التي تحظرها."),
                FwMode.Whitelist => L("Default deny: only programs with an Allow rule reach the network. New programs are stopped and you (or the auto-pilot) decide.", "المنع الافتراضي: لا يصل للشبكة إلا البرامج التي لها قاعدة سماح. البرامج الجديدة تُوقَف وتقرّر أنت (أو الطيار الآلي)."),
                _ => L("All traffic is cut except loopback. Use it when you suspect an active infection.", "يُقطع كل المرور عدا الاتصال المحلي. استخدمه عند الاشتباه بإصابة نشطة."),
            };
            modeBody.Children.Add(Text(desc, 13.5, Ink));
            var live = FirewallEngine.LiveState();
            var specs = FirewallEngine.BuildSpecs(s, store, DateTime.Now);
            modeBody.Children.Add(MonoText(L($"policy needs {specs.Count} filters · installed now: {(live.ok ? live.count.ToString() : "? (admin)")} · blocked-connection watcher: {BlockWatcher.Instance.Status}",
                $"السياسة تتطلب {specs.Count} مرشّحاً · المثبت الآن: {(live.ok ? live.count.ToString() : "؟ (مدير)")} · مراقب الاتصالات المحجوبة: {BlockWatcher.Instance.Status}"), 11.5, Steel));
            var mb = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
            mb.Children.Add(Button(L("Apply policy now", "تطبيق السياسة الآن"), ApplyFirewall, Kind.Primary, 13.5, Admin));
            mb.Children.Add(Button(L("Emergency: remove all Sour filters", "طوارئ: إزالة كل مرشّحات سور"), () =>
            {
                s.FirewallMode = FwMode.Off; Settings.Save();
                var r = FirewallEngine.RemoveAll(); Services.SyncBlockWatcher();
                MessageBox.Show(r.Ok ? L($"Removed {r.Removed} filters. The firewall is off.", $"أُزيل {r.Removed} مرشّحاً. الجدار متوقف.") : r.Error, "Sour"); Render();
            }, Kind.Danger, 13, Admin));
            modeBody.Children.Add(mb);
            Add(Section(L("Operating mode", "وضع التشغيل"), modeBody, L("Choose a mode, then apply. Changes are installed as one atomic transaction.", "اختر وضعاً ثم طبّق. تُثبَّت التغييرات كعملية واحدة غير قابلة للتجزئة.")));

            // ---- pending decisions
            List<PendingApp> pend; lock (BlockWatcher.Instance.Pending) pend = BlockWatcher.Instance.Pending.Values.OrderByDescending(p => p.Last).ToList();
            if (pend.Count > 0)
            {
                var pb = new StackPanel();
                foreach (var p in pend)
                {
                    var row = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };
                    var btns = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                    string path = p.Path;
                    btns.Children.Add(Button(L("Allow", "سماح"), () => { BlockWatcher.Instance.Decide(path, RuleAction.Allow); ApplyFirewall(); }, Kind.Good, 12.5));
                    btns.Children.Add(Button(L($"Allow {s.FwTempRuleMinutes} min", $"سماح {s.FwTempRuleMinutes} دقيقة"), () => { BlockWatcher.Instance.Decide(path, RuleAction.Allow, s.FwTempRuleMinutes); ApplyFirewall(); }, Kind.Ghost, 12.5));
                    btns.Children.Add(Button(L("Block", "حظر"), () => { BlockWatcher.Instance.Decide(path, RuleAction.Block); ApplyFirewall(); }, Kind.Danger, 12.5));
                    DockPanel.SetDock(btns, Dock.Right); row.Children.Add(btns);
                    var info = new StackPanel();
                    var line = new StackPanel { Orientation = Orientation.Horizontal };
                    line.Children.Add(Text(p.Name, 15, Ink, FontWeights.Bold));
                    string advice = p.Assessment?.Advice ?? "…";
                    line.Children.Add(new Border { Width = 10 });
                    line.Children.Add(Pill(L("AI advises: ", "نصيحة الذكاء: ") + (advice == "allow" ? L("allow", "سماح") : advice == "block" ? L("block", "حظر") : advice == "ask" ? L("your call", "قرارك") : "…"), advice == "allow" ? Moss : advice == "block" ? Red : Amber, advice == "ask" ? Ink : White));
                    info.Children.Add(line);
                    info.Children.Add(MonoText(p.Path, 11.5, Steel));
                    info.Children.Add(Text((p.Assessment?.Why ?? L("assessing…", "جارٍ التقييم…")) + "  ·  " + L($"{p.Attempts} attempts, last → {p.LastRemote}", $"{p.Attempts} محاولة، آخرها ← {p.LastRemote}"), 12.5, Ink));
                    row.Children.Add(info);
                    pb.Children.Add(row);
                }
                Add(Section(L("Waiting for your decision", "بانتظار قرارك"), pb, L("These programs tried to connect and were stopped.", "حاولت هذه البرامج الاتصال فأُوقفت.")));
            }

            // ---- rules
            var rows = store.Apps.OrderBy(r => r.Action).ThenBy(r => r.Name).Select(r => new RuleRow(r)).ToList();
            var grid = Table(rows, (L("Program", "البرنامج"), "Name", 170, false), (L("Rule", "القاعدة"), "Action", 120, false), (L("Publisher", "الناشر"), "Publisher", 170, false),
                (L("Set by", "المصدر"), "Source", 90, false), (L("Pinned SHA-256", "البصمة المثبّتة"), "Pin", 150, true), (L("Until", "حتى"), "Expires", 104, false), (L("Path", "المسار"), "Path", -1, true));
            var rb = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
            rb.Children.Add(Button(L("Allow a program…", "سماح لبرنامج…"), () => PickProgram(RuleAction.Allow), Kind.Good, 12.5));
            rb.Children.Add(Button(L("Block a program…", "حظر برنامج…"), () => PickProgram(RuleAction.Block), Kind.Danger, 12.5));
            rb.Children.Add(Button(L("Learn: allow signed programs seen online", "تعلّم: سماح للبرامج الموقَّعة التي ظهرت متصلة"), LearnFromSeen, Kind.Dark, 12.5));
            rb.Children.Add(Button(L("Switch allow/block", "تبديل سماح/حظر"), () => { if (grid.SelectedItem is RuleRow x) { x.R.Action = x.R.Action == RuleAction.Allow ? RuleAction.Block : RuleAction.Allow; x.R.HashChanged = false; RuleStore.Save(); Render(); } }, Kind.Ghost, 12.5));
            rb.Children.Add(Button(L("Allow inbound too", "سماح بالوارد أيضاً"), () => { if (grid.SelectedItem is RuleRow x) { x.R.AllowInbound = !x.R.AllowInbound; RuleStore.Save(); Render(); } }, Kind.Ghost, 12.5));
            rb.Children.Add(Button(L("Re-approve changed file", "إعادة اعتماد الملف المتغيّر"), () => { if (grid.SelectedItem is RuleRow x) { FirewallEngine.SetRule(x.R.Path, x.R.Action, x.R.Source); Render(); } }, Kind.Ghost, 12.5));
            rb.Children.Add(Button(L("Remove rule", "حذف القاعدة"), () => { if (grid.SelectedItem is RuleRow x) { FirewallEngine.RemoveRule(x.R.Id); Render(); } }, Kind.Ghost, 12.5));
            var rulesBody = new StackPanel();
            rulesBody.Children.Add(rows.Count == 0 ? Empty(L("No program rules yet. Add programs, or let Sour learn from the programs that are online now.", "لا قواعد بعد. أضف برامج، أو دع سور يتعلّم من البرامج المتصلة الآن.")) : grid);
            rulesBody.Children.Add(rb);
            Add(Section(L($"Program rules ({rows.Count})", $"قواعد البرامج ({rows.Count})"), rulesBody, L("A rule is bound to the file's SHA-256. If the file changes and the signer is not the same, the rule is suspended.", "القاعدة مرتبطة ببصمة الملف SHA-256. إن تغيّر الملف ولم يكن الموقِّع نفسه عُلّقت القاعدة.")));

            // ---- auto-pilot + options
            var ap = new StackPanel();
            ap.Children.Add(Segments(new List<(string, string)> { ("Off", L("Off — always ask me", "متوقف — اسألني دائماً")), ("Assist", L("Assist — auto-allow Windows parts, auto-block malware", "مساعد — سماح تلقائي لمكوّنات ويندوز وحظر تلقائي للخبيث")), ("Full", L("Full — also auto-allow validly signed clean programs", "كامل — وسماح تلقائي للبرامج الموقَّعة النظيفة")) },
                s.FwAutoPilot.ToString(), k => { s.FwAutoPilot = Enum.Parse<AutoPilot>(k); Settings.Save(); Render(); }));
            ap.Children.Add(Text(L("For each new program the auto-pilot checks the code signature, runs the antivirus engines (rules + AI model) and looks at where the file lives. Unsigned or suspicious programs are never auto-allowed.",
                "لكل برنامج جديد يفحص الطيار الآلي التوقيع الرقمي، ويشغّل محركات مكافحة الفيروسات (القواعد + نموذج الذكاء)، وينظر في مكان الملف. البرامج غير الموقَّعة أو المشبوهة لا يُسمح لها تلقائياً أبداً."), 12.5, Steel));
            Add(Section(L("AI auto-pilot", "الطيار الآلي بالذكاء الاصطناعي"), ap));

            void Opt(Panel host, string en, string ar, string hen, string har, Func<bool> get, Action<bool> set) => host.Children.Add(Toggle(L(en, ar), L(hen, har), get(), v => { set(v); Settings.Save(); }));
            var o1 = new StackPanel(); var o2 = new StackPanel { Margin = new Thickness(24, 0, 0, 0) };
            Opt(o1, "Keep enforcing when Sour is closed", "استمرار الفرض عند إغلاق سور", "Filters are stored in Windows and survive restarts.", "تُحفظ المرشّحات في ويندوز وتبقى بعد إعادة التشغيل.", () => s.FwPersistent, v => s.FwPersistent = v);
            Opt(o1, "Stealth: drop unsolicited inbound", "التخفّي: إسقاط الوارد غير المطلوب", "Only programs you allow inbound can accept connections.", "لا يقبل الاتصالات الواردة إلا البرامج المسموح لها بذلك.", () => s.FwBlockInbound, v => s.FwBlockInbound = v);
            Opt(o1, "Allow core network services", "السماح بخدمات الشبكة الأساسية", "DNS, DHCP, time sync, ICMP. Needed to stay online in whitelist mode.", "DNS و DHCP ومزامنة الوقت و ICMP. لازمة للبقاء متصلاً في وضع القائمة البيضاء.", () => s.FwAllowCoreServices, v => s.FwAllowCoreServices = v);
            Opt(o1, "Allow the local network", "السماح بالشبكة المحلية", "Printers and shared folders keep working in whitelist mode.", "تبقى الطابعات والمجلدات المشتركة تعمل في وضع القائمة البيضاء.", () => s.FwAllowLan, v => s.FwAllowLan = v);
            Opt(o2, "Hash pinning", "تثبيت البصمة", "Suspend an Allow rule when its program file is replaced.", "تعليق قاعدة السماح عند استبدال ملف البرنامج.", () => s.FwHashPinning, v => s.FwHashPinning = v);
            Opt(o2, "Trust Windows components", "الثقة بمكوّنات ويندوز", "Lets the auto-pilot allow Microsoft-signed system binaries.", "يسمح للطيار الآلي بإجازة ملفات النظام الموقَّعة من مايكروسوفت.", () => s.FwTrustMicrosoft, v => s.FwTrustMicrosoft = v);
            Opt(o2, "Show blocked connections", "إظهار الاتصالات المحجوبة", "Turns on Windows connection auditing (failures only) so Sour can ask about blocked programs.", "يفعّل تدقيق الاتصالات في ويندوز (الإخفاقات فقط) ليسألك سور عن البرامج المحجوبة.", () => s.FwAuditEvents, v => s.FwAuditEvents = v);
            var og = new UniformGrid { Columns = 2 }; og.Children.Add(o1); og.Children.Add(o2);
            Add(Section(L("Options", "الخيارات"), og, L("Press “Apply policy now” after changing options.", "اضغط «تطبيق السياسة الآن» بعد تغيير الخيارات.")));

            // ---- IP block list
            var ipRows = store.BlockedIps.Select(i => new IpRow { R = i, Cidr = i.Cidr, Note = i.Note }).ToList();
            var ipGrid = Table(ipRows, (L("Address / range", "العنوان / النطاق"), "Cidr", 240, true), (L("Note", "ملاحظة"), "Note", -1, false));
            ipGrid.MaxHeight = 220;
            var ipIn = Input("", 220, "203.0.113.0/24"); var noteIn = Input("", 220, "note"); noteIn.FontFamily = BodyFont; noteIn.FlowDirection = FlowDirection;
            var ipBar = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
            ipBar.Children.Add(ipIn); ipBar.Children.Add(noteIn);
            ipBar.Children.Add(Button(L("Block address", "حظر العنوان"), () =>
            {
                if (!FirewallEngine.TryParseCidr(ipIn.Text, out _, out _)) { MessageBox.Show(L("Enter an IPv4/IPv6 address or CIDR range, e.g. 203.0.113.0/24", "أدخل عنوان IPv4/IPv6 أو نطاق CIDR مثل ‎203.0.113.0/24"), "Sour"); return; }
                store.BlockedIps.Add(new IpRule { Cidr = ipIn.Text.Trim(), Note = noteIn.Text.Trim() }); RuleStore.Save(); Render();
            }, Kind.Danger, 12.5));
            ipBar.Children.Add(Button(L("Remove selected", "حذف المحدد"), () => { if (ipGrid.SelectedItem is IpRow x) { store.BlockedIps.Remove(x.R); RuleStore.Save(); Render(); } }, Kind.Ghost, 12.5));
            var ipBody = new StackPanel();
            ipBody.Children.Add(ipRows.Count == 0 ? Empty(L("No blocked addresses. Threat-feed addresses appear here after an update (Settings).", "لا عناوين محظورة. تظهر هنا عناوين قوائم التهديدات بعد التحديث (الإعدادات).")) : ipGrid);
            ipBody.Children.Add(ipBar);
            Add(Section(L($"Blocked addresses ({ipRows.Count})", $"العناوين المحظورة ({ipRows.Count})"), ipBody, L("Blocked for every program, in both directions, even for allowed programs.", "محظورة على كل البرامج وفي الاتجاهين، حتى على البرامج المسموح لها.")));
        }

        void PickProgram(RuleAction action)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Filter = "Programs (*.exe)|*.exe|All files (*.*)|*.*", Title = "Sour" };
            if (dlg.ShowDialog(this) != true) return;
            FirewallEngine.SetRule(dlg.FileName, action);
            Render();
        }

        void LearnFromSeen()
        {
            int added = 0, skipped = 0;
            foreach (string path in Services.SeenApps.Keys.ToList())
            {
                if (!File.Exists(path) || RuleStore.Current.Find(path) != null) continue;
                var a = AutoPilotEngine.Assess(path);
                if (a.Advice == "allow") { FirewallEngine.SetRule(path, RuleAction.Allow, "learn"); added++; } else skipped++;
            }
            MessageBox.Show(L($"{added} signed, clean programs were given Allow rules.\n{skipped} unsigned or suspicious programs were left for you to decide.",
                $"مُنحت قواعد سماح لـ {added} برنامجاً موقَّعاً ونظيفاً.\nتُرك {skipped} برنامجاً غير موقَّع أو مشبوهاً لقرارك."), "Sour");
            Render();
        }

        // ------------------------------------------------------------------ 03 connections
        public sealed class ConnRow
        {
            public Conn C;
            public string Process { get; } public string Pid { get; } public string Host { get; } public string Address { get; } public string Port { get; } public string Proto { get; } public string State { get; } public string Risk { get; } public string Why { get; }
            public ConnRow(Conn c)
            {
                C = c; Process = c.ProcessName; Pid = c.Pid.ToString(); Host = c.Host ?? ""; Address = c.Remote?.ToString() ?? ""; Port = c.RemotePort.ToString(); Proto = c.Protocol; State = c.State;
                Risk = c.Risk >= 1 ? c.Risk.ToString("0") : "·"; Why = c.RiskWhy ?? "";
            }
        }

        public sealed class ListenRow { public string Process { get; set; } public string Pid { get; set; } public string Proto { get; set; } public string Port { get; set; } public string Address { get; set; } public string Exposure { get; set; } public bool Open; }

        void PageConnections()
        {
            var filter = Input("", 280, L("filter by program, host or address", "تصفية بالبرنامج أو النطاق أو العنوان"));
            var onlyRisk = false;
            DataGrid grid = null;
            var count = MonoText("", 11.5, Steel);
            List<ConnRow> Rows()
            {
                string f = filter.Text.Trim();
                var q = Services.Conn.Current.Where(c => !c.IsListener && c.Remote != null && !System.Net.IPAddress.IsLoopback(c.Remote));
                if (onlyRisk) q = q.Where(c => c.Risk >= 30);
                if (f != "") q = q.Where(c => (c.ProcessName ?? "").Contains(f, StringComparison.OrdinalIgnoreCase) || (c.Host ?? "").Contains(f, StringComparison.OrdinalIgnoreCase) || c.Remote.ToString().Contains(f));
                return q.OrderByDescending(c => c.Risk).ThenBy(c => c.ProcessName).Select(c => new ConnRow(c)).ToList();
            }
            grid = Table(Rows(), (L("Program", "البرنامج"), "Process", 170, false), ("PID", "Pid", 62, true), (L("Host", "النطاق"), "Host", 220, true), (L("Address", "العنوان"), "Address", 170, true),
                (L("Port", "المنفذ"), "Port", 60, true), (L("Proto", "البروتوكول"), "Proto", 60, true), (L("AI risk", "خطورة الذكاء"), "Risk", 74, true), (L("Why", "السبب"), "Why", -1, false));
            grid.MaxHeight = 520;
            void Refresh(bool force)
            {
                if (!force && grid.SelectedItem != null) return;      // do not pull the row away while the user is acting on it
                var rows = Rows(); grid.ItemsSource = rows;
                var all = Services.Conn.Current;
                count.Text = L($"{rows.Count} shown · {all.Count(c => !c.IsListener)} connections · {all.Count(c => c.IsListener)} listening ports · {Services.Conn.TotalSeen} seen since start",
                    $"المعروض {rows.Count} · {all.Count(c => !c.IsListener)} اتصالاً · {all.Count(c => c.IsListener)} منفذاً مُنصتاً · {Services.Conn.TotalSeen} منذ البدء");
            }
            filter.TextChanged += (_, _) => Refresh(true);
            var bar = new WrapPanel();
            bar.Children.Add(filter);
            bar.Children.Add(Button(L("Only risky", "الخطِرة فقط"), () => { onlyRisk = !onlyRisk; Refresh(true); }, Kind.Ghost, 12.5));
            bar.Children.Add(Button(L("Block this program", "حظر هذا البرنامج"), () => { if (grid.SelectedItem is ConnRow x && File.Exists(x.C.ProcessPath)) { FirewallEngine.SetRule(x.C.ProcessPath, RuleAction.Block); grid.SelectedItem = null; Note(L("Block rule saved. Apply the policy on the Firewall page.", "حُفظت قاعدة الحظر. طبّق السياسة من صفحة الجدار الناري.")); } }, Kind.Danger, 12.5));
            bar.Children.Add(Button(L("Allow this program", "سماح لهذا البرنامج"), () => { if (grid.SelectedItem is ConnRow x && File.Exists(x.C.ProcessPath)) { FirewallEngine.SetRule(x.C.ProcessPath, RuleAction.Allow); grid.SelectedItem = null; Note(L("Allow rule saved.", "حُفظت قاعدة السماح.")); } }, Kind.Good, 12.5));
            bar.Children.Add(Button(L("Block this address", "حظر هذا العنوان"), () => { if (grid.SelectedItem is ConnRow x) { RuleStore.Current.BlockedIps.Add(new IpRule { Cidr = x.Address, Note = x.Host + " via " + x.Process }); RuleStore.Save(); grid.SelectedItem = null; Note(L("Address added to the block list.", "أُضيف العنوان لقائمة الحظر.")); } }, Kind.Ghost, 12.5));
            bar.Children.Add(Button(L("Scan this program", "فحص هذا البرنامج"), () => { if (grid.SelectedItem is ConnRow x && File.Exists(x.C.ProcessPath)) { var r = Scanner.Instance.ScanFile(x.C.ProcessPath, false); ShowResult(r); } }, Kind.Ghost, 12.5));
            bar.Children.Add(Button(L("Clear selection", "إلغاء التحديد"), () => { grid.SelectedItem = null; Refresh(true); }, Kind.Ghost, 12.5));
            var body = new StackPanel();
            body.Children.Add(bar); body.Children.Add(grid); body.Children.Add(new Border { Height = 8 }); body.Children.Add(count);
            Add(Section(L("Who is talking to whom", "من يتصل بمن"), body, L("Host names come from the Windows DNS cache; no lookup leaves the PC. Select a row to act on it (the list pauses while a row is selected).", "أسماء النطاقات من ذاكرة DNS في ويندوز؛ لا يخرج أي استعلام من الجهاز. حدّد صفاً للتصرف فيه (تتوقف القائمة مؤقتاً أثناء التحديد).")));
            var listeners = Services.Conn.Current.Where(c => c.IsListener && c.Pid != 0 && c.Local != null)
                .GroupBy(c => c.Pid + "|" + c.Protocol + "|" + c.LocalPort).Select(g => g.First())
                .Select(c => new ListenRow
                {
                    Process = c.ProcessName, Pid = c.Pid.ToString(), Proto = c.Protocol, Port = c.LocalPort.ToString(), Address = c.Local.ToString(),
                    Open = c.Local.Equals(System.Net.IPAddress.Any) || c.Local.Equals(System.Net.IPAddress.IPv6Any),
                }).OrderByDescending(r => r.Open).ThenBy(r => int.Parse(r.Port)).ToList();
            foreach (var r in listeners) r.Exposure = r.Open ? L("reachable from the network", "يمكن الوصول إليه من الشبكة") : L("this PC only", "هذا الجهاز فقط");
            var lg = Table(listeners, (L("Program", "البرنامج"), "Process", 200, false), ("PID", "Pid", 70, true), (L("Proto", "البروتوكول"), "Proto", 70, true),
                (L("Port", "المنفذ"), "Port", 80, true), (L("Listens on", "ينصت على"), "Address", 220, true), (L("Exposure", "الانكشاف"), "Exposure", -1, false));
            lg.MaxHeight = 320;
            Add(Section(L($"Open ports ({listeners.Count(r => r.Open)} reachable from the network, {listeners.Count} in total)", $"المنافذ المفتوحة ({listeners.Count(r => r.Open)} مكشوفة للشبكة من أصل {listeners.Count})"), lg,
                L("Programs waiting for incoming connections. With stealth inbound on, only programs you allow inbound can be reached.", "برامج تنتظر اتصالات واردة. مع تفعيل التخفّي لا يُوصَل إلا للبرامج المسموح لها بالوارد.")));
            Refresh(true);
            _tick = () => Refresh(false);
        }

        void Note(string text) => MessageBox.Show(text, "Sour");

        void ShowResult(ScanResult r)
        {
            var w = new Window { Title = "Sour", Width = 760, Height = 560, Owner = this, Background = Stone, FlowDirection = FlowDirection, WindowStartupLocation = WindowStartupLocation.CenterOwner };
            var sp = new StackPanel { Margin = new Thickness(20) };
            sp.Children.Add(ResultCard(r, false));
            w.Content = new ScrollViewer { Content = sp, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            w.ShowDialog();
        }
    }
}
