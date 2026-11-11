using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Sour.Av;
using Sour.Core;
using Sour.Fw;

namespace Sour.Ui
{
    public static class AppHost
    {
        static System.Windows.Forms.NotifyIcon _tray;
        static MainWindow _win;
        static bool _exiting;

        /// <summary>The wall mark as a 32×32 icon (drawn, so no image file is needed).</summary>
        static System.Drawing.Icon MakeIcon()
        {
            // the icon embedded in Sour.exe (Assets/sour.ico); the drawn fallback below is only for a build without it
            try { var embedded = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath); if (embedded != null) return embedded; } catch { }
            using var bmp = new System.Drawing.Bitmap(32, 32);
            using (var g = System.Drawing.Graphics.FromImage(bmp))
            {
                g.Clear(System.Drawing.Color.FromArgb(0x11, 0x13, 0x17));
                var brick = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(0xD9, 0x43, 0x1E));
                for (int row = 0; row < 3; row++)
                {
                    int y = 5 + row * 8, off = row % 2 == 0 ? 3 : -4;
                    for (int x = off; x < 29; x += 14)
                    {
                        int left = Math.Max(x, 3), right = Math.Min(x + 12, 29);
                        if (right - left > 1) g.FillRectangle(brick, left, y, right - left, 6);
                    }
                }
            }
            return System.Drawing.Icon.FromHandle(bmp.GetHicon());
        }

        static ImageSource IconSource()
        {
            using var ico = MakeIcon();
            return System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(ico.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
        }

        /// <summary>"Scan with Sour" from Explorer: a stand-alone window that scans the given paths and shows the verdicts.</summary>
        static int RunScanUi(string[] paths)
        {
            var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
            var w = new MainWindow { Icon = IconSource() };
            app.MainWindow = w;
            w.Go("antivirus");
            w.Show();
            w.StartScan(paths.Where(p => File.Exists(p) || Directory.Exists(p)).ToList(), true);
            app.Run();
            return 0;
        }

        public static int Run(string[] args)
        {
            if (args.Length > 0 && args[0] == "--scan-ui") return RunScanUi(args.Skip(1).ToArray());
            using var single = new Mutex(true, "Local\\SourFirewallSingleInstance", out bool first);
            if (!first) { MessageBox.Show(I18n.T("Sour is already running (look in the notification area).", "سور يعمل مسبقاً (انظر منطقة الإشعارات)."), "Sour"); return 0; }

            var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            app.DispatcherUnhandledException += (_, e) => { Log.Debug("ui: " + e.Exception); e.Handled = true; };
            Services.Start();
            _win = new MainWindow { Icon = IconSource() };
            _win.Closing += (_, e) =>
            {
                if (_exiting) return;
                e.Cancel = true; _win.Hide();        // keep protecting from the notification area
                if (Settings.Current.Notifications) _tray?.ShowBalloonTip(3000, "Sour", I18n.T("Still protecting. Right-click the wall icon to exit.", "ما زال يحمي. انقر بالزر الأيمن على أيقونة السور للخروج."), System.Windows.Forms.ToolTipIcon.Info);
            };

            _tray = new System.Windows.Forms.NotifyIcon { Icon = MakeIcon(), Visible = true, Text = "Sour — AI firewall + antivirus" };
            var menu = new System.Windows.Forms.ContextMenuStrip();
            menu.Items.Add(I18n.T("Open Sour", "فتح سور"), null, (_, _) => Show());
            menu.Items.Add(I18n.T("Quick scan", "فحص سريع"), null, (_, _) => { Show(); _win.Go("antivirus"); _win.StartScan(Scanner.QuickScanRoots().ToList(), false); });
            menu.Items.Add(I18n.T("Exit", "خروج"), null, (_, _) => { _exiting = true; _tray.Visible = false; Services.Stop(); app.Shutdown(); });
            _tray.ContextMenuStrip = menu;
            _tray.DoubleClick += (_, _) => Show();

            Log.Added += e =>
            {
                if (e.Level < Severity.High || !Settings.Current.Notifications) return;
                try { _win.Dispatcher.BeginInvoke(new Action(() => _tray.ShowBalloonTip(5000, "Sour — " + T.SeverityText(e.Level), e.Title, e.Level == Severity.Critical ? System.Windows.Forms.ToolTipIcon.Error : System.Windows.Forms.ToolTipIcon.Warning))); } catch { }
            };

            if (!args.Contains("--minimized") && !Settings.Current.StartMinimized) _win.Show();
            app.Run();
            _tray.Dispose();
            return 0;
        }

        static void Show() { _win.Show(); if (_win.WindowState == WindowState.Minimized) _win.WindowState = WindowState.Normal; _win.Activate(); }

        // ------------------------------------------------------------------ screenshots for the guide / visual checks
        static void Pump()
        {
            for (int i = 0; i < 3; i++)
            {
                var frame = new DispatcherFrame();
                Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
                Dispatcher.PushFrame(frame);
            }
        }

        /// <summary>Fills a scratch profile with representative data so that every screen shows its real layout.</summary>
        static void SeedDemo()
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string sys = Path.Combine(win, "System32");
            var s = Settings.Current;
            s.FirewallMode = FwMode.Whitelist; s.AvRealtime = true; s.AvProcessWatch = true; s.AvRansomShield = false; s.FwAutoPilot = AutoPilot.Assist;
            foreach (string f in new[] { "svchost.exe", "curl.exe", "mstsc.exe", "OpenSSH\\ssh.exe" })
                if (File.Exists(Path.Combine(sys, f))) FirewallEngine.SetRule(Path.Combine(sys, f), RuleAction.Allow, f == "svchost.exe" ? "autopilot" : "user");
            if (File.Exists(Path.Combine(sys, "ftp.exe"))) FirewallEngine.SetRule(Path.Combine(sys, "ftp.exe"), RuleAction.Block);
            RuleStore.Current.BlockedIps.Add(new IpRule { Cidr = "203.0.113.0/24", Note = "documentation range (demo)" });
            RuleStore.Current.BlockedIps.Add(new IpRule { Cidr = "198.51.100.77", Note = "feed:feodo" });

            string unknown = Path.Combine(AppContext.BaseDirectory, "Sour.dll");
            lock (BlockWatcher.Instance.Pending)
                BlockWatcher.Instance.Pending[unknown] = new PendingApp { Path = unknown, Name = "updater-helper.exe", Attempts = 7, LastRemote = "198.51.100.23:8443", Assessment = AutoPilotEngine.Assess(unknown) };

            var det = new ScanResult { Path = @"C:\Users\user\Downloads\invoice_2026.pdf.exe", Kind = "pe", Size = 482304, Sha256 = "9f2c4a7d1e8b3f60a5c9d2e7b4f1a8c3d6e9b2f5a8c1d4e7b0a3f6c9d2e5b8a1", Score = 100, Verdict = Verdict.Malicious, MlProb = 0.9973, Signer = "unsigned" };
            det.Reasons.Add(new Reason("ML.Malicious", 94, "AI model: 99.7% malicious ← sec_max_entropy, imp_n_func_log, checksum_zero", "نموذج الذكاء الاصطناعي: احتمال الخبث 99.7% ← sec_max_entropy, imp_n_func_log, checksum_zero"));
            det.Reasons.Add(new Reason("Heur.DoubleExtension", 40, "Double extension (.pdf.exe) - a program posing as a document", "امتداد مزدوج (.pdf.exe) - برنامج يتنكّر كمستند"));
            det.Reasons.Add(new Reason("Heur.Packed", 25, "Packed/protected with UPX", "مضغوط/محمي بواسطة UPX"));
            det.Reasons.Add(new Reason("Heur.FewImports", 15, "Almost no imported functions (2) - imports are resolved at run time", "لا يستورد دوالّ تقريباً (2) - يحلّ الاستيرادات وقت التشغيل"));
            det.MlTop = new List<(string, double, double)> { ("sec_max_entropy", 2.31, 7.94), ("imp_n_func_log", 1.72, 1.10), ("checksum_zero", 0.96, 1), ("sec_wx", 0.74, 2), ("dd_SECURITY_log", 0.51, 0) };
            lock (Guard.Instance.Pending) Guard.Instance.Pending.Add(new Detection { Result = det, Source = "file guard" });

            var sus = new ScanResult { Path = @"C:\Users\user\Desktop\setup-helper.ps1", Kind = "script", Size = 9120, Sha256 = "3b7e1c9a5d2f8e4b6a0c3d7f1e5b9a2c4d8f0e6b3a7c1d5f9e2b6a0c4d8f1e3b", Score = 60, Verdict = Verdict.Suspicious };
            det = sus;
            sus.Reasons.Add(new Reason("SOUR.PS.EncodedCommand", 60, "Launches PowerShell with an encoded (hidden) command [T1027]", "تشغيل PowerShell بأمر مرمَّز لإخفاء محتواه [T1027]"));
            sus.Reasons.Add(new Reason("Heur.Script.Base64Blob", 25, "Embeds a 4200-character Base64 blob", "يتضمن كتلة Base64 بطول 4200 حرفاً"));
            _demoFindings = new List<ScanResult> { sus };

            string qf = Path.Combine(Paths.Root, "demo_sample.bin");
            File.WriteAllText(qf, "harmless demo content for the quarantine screen");
            Quarantine.Add(new ScanResult { Path = qf, Verdict = Verdict.Malicious, Score = 92, Reasons = { new Reason("SOUR.Miner.Generic", 92, "Cryptocurrency miner configuration", "إعدادات برنامج تعدين عملات رقمية") } });

            var t0 = DateTime.Now.AddHours(-3); var rnd = new Random(5);
            foreach (var (app, port, host) in new[] { ("chrome.exe", 443, "www.example.com"), ("Teams.exe", 443, "teams.example.net"), ("svchost.exe", 443, "update.example.org"), ("outlook.exe", 993, "mail.example.com") })
                for (int i = 0; i < 45; i++)
                    Services.NetAi.Observe(new Conn { Pid = 1, ProcessPath = @"C:\Program Files\App\" + app, Protocol = "TCP", Remote = IPAddress.Parse($"93.184.{rnd.Next(4)}.{rnd.Next(1, 250)}"), RemotePort = i % 9 == 0 ? 80 : port, Host = host }, t0.AddSeconds(i * 61 + rnd.Next(50)));

            Log.Add(EventKind.Firewall, Severity.Info, "fw.applied", "Firewall policy applied: Whitelist", "تم تطبيق سياسة الجدار الناري: القائمة البيضاء", "ok: 46 filters installed");
            Log.Add(EventKind.Ai, Severity.Info, "ap.allow", "Auto-pilot allowed svchost.exe", "الطيار الآلي سمح لـ svchost.exe", "Signed Windows / Microsoft component");
            Log.Add(EventKind.Firewall, Severity.Low, "fw.blocked", "Blocked outbound connection of updater-helper.exe — decision needed", "حُجب اتصال صادر لـ updater-helper.exe — بانتظار قرارك", "→ 198.51.100.23:8443");
            Log.Add(EventKind.Network, Severity.Medium, "net.anomaly", "Unusual connection by notepad.exe (risk 72)", "اتصال غير معتاد من notepad.exe (خطورة 72)", "→ 198.51.100.7:4444 · port 4444 never used by this app · direct IP connection");
            Log.Add(EventKind.Antivirus, Severity.Critical, "av.malicious", "Threat found (file guard): ML.Malicious", "تهديد (حارس الملفات): ML.Malicious", det.Path);
            Log.Add(EventKind.Persistence, Severity.Medium, "ps.autorun", "New program registered to start with Windows", "برنامج جديد سُجّل ليعمل مع بدء ويندوز", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Helper");
            Log.Add(EventKind.Ransomware, Severity.Info, "rs.on", "Ransomware shield armed (decoy files placed)", "درع الفدية مفعّل (وُضعت ملفات الطُّعم)");
        }
        static List<ScanResult> _demoFindings;

        public static int Snap(string dir)
        {
            Directory.CreateDirectory(dir);
            string scratch = Path.Combine(Path.GetTempPath(), "sour_snap_" + Environment.ProcessId);
            Paths.OverrideRoot = Path.Combine(scratch, "root");
            Settings.Reload(); RuleStore.Reload(); Quarantine.Reload(); HashDb.Reload();
            Log.Persist = false;
            var log = new List<string>();
            try
            {
                var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                Settings.Current.AvUseAmsi = false;
                SeedDemo();
                Services.Conn.NewConnection += c => { };
                Services.Conn.Tick(); Thread.Sleep(300); Services.Conn.Tick();
                foreach (var c in Services.Conn.Current.Where(c => !c.IsListener).Take(400)) { var v = Services.NetAi.Observe(c, DateTime.Now); c.Risk = v.Score; c.RiskWhy = v.Why; }

                foreach (string lang in new[] { "ar", "en" })
                {
                    Settings.Current.Language = lang;
                    var w = new MainWindow();
                    w.ScanFindings = _demoFindings.ToList();
                    foreach (string page in MainWindow.PageIds)
                    {
                        w.Go(page);
                        var root = (FrameworkElement)w.Content;
                        w.Content = null;
                        root.FlowDirection = lang == "ar" ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;
                        var host = new System.Windows.Controls.Border { Child = root, Background = T.Stone, Width = 1320 };
                        // first pass with a tall viewport to learn the content height, second pass at that height
                        double h = 3600;
                        for (int pass = 0; pass < 2; pass++)
                        {
                            host.Height = h;
                            host.Measure(new Size(1320, h)); host.Arrange(new Rect(0, 0, 1320, h)); host.UpdateLayout(); Pump();
                            double content = w.BodyHeight + 130;
                            h = Math.Max(760, Math.Min(3600, Math.Ceiling(content)));
                        }
                        host.Height = h; host.Measure(new Size(1320, h)); host.Arrange(new Rect(0, 0, 1320, h)); host.UpdateLayout(); Pump();
                        var rtb = new RenderTargetBitmap(1320, (int)h, 96, 96, PixelFormats.Pbgra32);
                        rtb.Render(host);
                        var enc = new PngBitmapEncoder(); enc.Frames.Add(BitmapFrame.Create(rtb));
                        string file = Path.Combine(dir, $"{lang}_{Array.IndexOf(MainWindow.PageIds, page) + 1:00}_{page}.png");
                        using (var fs = File.Create(file)) enc.Save(fs);
                        log.Add($"{lang} {page}: {1320}x{(int)h} texts={w.CountTexts()} ok");
                        host.Child = null; w.Content = root;
                    }
                    w.Close();
                }
            }
            catch (Exception ex) { log.Add("ERROR " + ex); }
            finally
            {
                File.WriteAllLines(Path.Combine(dir, "snap_log.txt"), log);
                Services.Stop();
                try { Directory.Delete(scratch, true); } catch { }
            }
            return log.Any(l => l.StartsWith("ERROR")) ? 1 : 0;
        }
    }
}
