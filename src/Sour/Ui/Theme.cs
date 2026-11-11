using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using Sour.Core;

namespace Sour.Ui
{
    /// <summary>
    /// Visual system "the wall": ink-black rail, stone background, paper cards with hard square shadows,
    /// brick-orange as the single accent, heavy condensed numerals. No gradients, no rounded corners, no emoji.
    /// </summary>
    public static class T
    {
        public static readonly Brush Ink = B("#111317"), Ink2 = B("#1C2026"), Stone = B("#ECE6DA"), Paper = B("#FBF8F1"), Brick = B("#D9431E"),
            BrickDark = B("#A83212"), Moss = B("#1E7A46"), Amber = B("#D99A06"), Steel = B("#5E6672"), Hair = B("#C9C1B1"), White = B("#FFFFFF"),
            Red = B("#B3261E"), Mute = B("#8C8576"), RowAlt = B("#F3EEE3"), Sel = B("#F6D9CF");

        public static readonly FontFamily BodyFont = new FontFamily("Bahnschrift, Noto Sans Arabic, Segoe UI");
        public static readonly FontFamily Head = new FontFamily("Bahnschrift SemiBold Condensed, Noto Kufi Arabic, Bahnschrift, Segoe UI");
        public static readonly FontFamily Mono = new FontFamily("Cascadia Mono, Consolas, Noto Sans Arabic");

        static Brush B(string hex) { var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex); b.Freeze(); return b; }
        public static string L(string en, string ar) => I18n.T(en, ar);
        /// <summary>Monospace for Latin labels; Arabic has no good monospace, so labels fall back to the body face.</summary>
        public static FontFamily LabelFont => I18n.IsArabic ? BodyFont : Mono;

        public static TextBlock Text(string s, double size = 13.5, Brush color = null, FontWeight? weight = null, FontFamily font = null, bool wrap = true)
            => new TextBlock { Text = s ?? "", FontSize = size, Foreground = color ?? Ink, FontWeight = weight ?? FontWeights.Normal, FontFamily = font ?? BodyFont, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap, VerticalAlignment = VerticalAlignment.Center };

        public static TextBlock H(string s, double size = 22, Brush color = null) => new TextBlock { Text = s, FontSize = size, FontFamily = Head, FontWeight = FontWeights.Bold, Foreground = color ?? Ink, TextWrapping = TextWrapping.Wrap };

        /// <summary>Small uppercase label that sits above a value or a section.</summary>
        public static TextBlock Label(string s, Brush color = null) => new TextBlock { Text = I18n.IsArabic ? s : s.ToUpperInvariant(), FontSize = I18n.IsArabic ? 12.5 : 11, FontFamily = LabelFont, Foreground = color ?? Steel, Margin = new Thickness(0, 0, 0, 4) };

        static bool HasArabic(string s) { if (s != null) foreach (char ch in s) if (ch >= 0x600 && ch <= 0x6FF) return true; return false; }

        /// <summary>Technical text (paths, hashes, counters). Monospace for Latin; text that contains Arabic uses the body face, right-to-left.</summary>
        public static TextBlock MonoText(string s, double size = 12, Brush color = null)
        {
            bool ar = HasArabic(s);
            return new TextBlock { Text = s ?? "", FontSize = ar ? size + 0.5 : size, FontFamily = ar ? BodyFont : Mono, Foreground = color ?? Ink, FlowDirection = ar ? FlowDirection.RightToLeft : FlowDirection.LeftToRight, TextWrapping = TextWrapping.Wrap, TextAlignment = ar ? TextAlignment.Left : I18n.IsArabic ? TextAlignment.Right : TextAlignment.Left };
        }

        /// <summary>Flat panel with a hairline frame. An accent, when given, is a thick stripe on the leading edge.</summary>
        public static FrameworkElement Card(UIElement child, Brush accent = null, double pad = 16, Brush background = null)
            => new Border
            {
                Background = background ?? Paper, BorderBrush = accent ?? Hair, BorderThickness = accent != null ? new Thickness(5, 1, 1, 1) : new Thickness(1),
                Padding = new Thickness(pad), Child = child,
            };

        /// <summary>A titled block: small heavy title on a ruled line, then the content. The hint becomes a tooltip.</summary>
        public static FrameworkElement Section(string title, UIElement body, string hint = null, UIElement right = null)
        {
            var sp = new StackPanel();
            var head = new DockPanel { LastChildFill = true };
            if (right != null) { DockPanel.SetDock(right, Dock.Right); head.Children.Add(right); }
            var t = new TextBlock { Text = title, FontFamily = BodyFont, FontWeight = FontWeights.Bold, FontSize = 14.5, Foreground = Ink, VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(0, 0, 0, 5) };
            if (!string.IsNullOrEmpty(hint)) t.ToolTip = hint;
            head.Children.Add(t);
            sp.Children.Add(head);
            sp.Children.Add(new Border { Height = 2, Background = Ink, Margin = new Thickness(0, 0, 0, 12) });
            sp.Children.Add(body);
            return sp;
        }

        public enum Kind { Primary, Dark, Ghost, Danger, Good }

        public static Border Button(string text, Action click, Kind kind = Kind.Dark, double size = 13, bool enabled = true)
        {
            Brush bg = kind switch { Kind.Primary => Brick, Kind.Dark => Ink, Kind.Danger => Red, Kind.Good => Moss, _ => Paper };
            Brush fg = kind == Kind.Ghost ? Ink : White;
            Brush hover = kind switch { Kind.Primary => BrickDark, Kind.Dark => Ink2, Kind.Danger => B("#8C1C16"), Kind.Good => B("#165C34"), _ => Stone };
            var b = new Border
            {
                Background = enabled ? bg : Hair, BorderBrush = Ink, BorderThickness = new Thickness(kind == Kind.Ghost ? 2 : 0), Padding = new Thickness(14, 8, 14, 8),
                Margin = new Thickness(0, 0, 8, 8), Cursor = enabled ? Cursors.Hand : Cursors.Arrow, VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Left,
                Child = new TextBlock { Text = text, FontFamily = BodyFont, FontWeight = FontWeights.SemiBold, FontSize = size, Foreground = enabled ? fg : Mute, TextAlignment = TextAlignment.Center },
                Tag = text,
            };
            if (enabled)
            {
                b.MouseEnter += (_, _) => b.Background = hover;
                b.MouseLeave += (_, _) => b.Background = bg;
                b.MouseLeftButtonUp += (_, e) => { e.Handled = true; try { click?.Invoke(); } catch (Exception ex) { MessageBox.Show(ex.Message, "Sour"); } };
            }
            return b;
        }

        /// <summary>Square on/off switch with a label and an optional explanation line.</summary>
        public static FrameworkElement Toggle(string label, string hint, bool value, Action<bool> changed, bool enabled = true)
        {
            bool state = value;
            var knob = new Border { Width = 18, Height = 18, Background = White, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(2) };
            var track = new Border { Width = 44, Height = 22, BorderBrush = Ink, BorderThickness = new Thickness(0), Child = knob, Cursor = Cursors.Hand, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 2, 12, 0), FlowDirection = FlowDirection.LeftToRight };
            void Paint() { track.Background = !enabled ? Hair : state ? Moss : Steel; knob.HorizontalAlignment = state ? HorizontalAlignment.Right : HorizontalAlignment.Left; }
            Paint();
            var texts = new StackPanel();
            texts.Children.Add(Text(label, 13.5, Ink, FontWeights.SemiBold));
            if (!string.IsNullOrEmpty(hint)) texts.Children.Add(Text(hint, 12, Steel));
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 12), Background = Brushes.Transparent, Tag = label };
            DockPanel.SetDock(track, Dock.Left); row.Children.Add(track); row.Children.Add(texts);
            if (enabled) row.MouseLeftButtonUp += (_, _) => { state = !state; Paint(); try { changed(state); } catch (Exception ex) { MessageBox.Show(ex.Message, "Sour"); } };
            return row;
        }

        /// <summary>Row of mutually exclusive square buttons.</summary>
        public static FrameworkElement Segments(IList<(string key, string text)> options, string selected, Action<string> pick, bool enabled = true)
        {
            var wp = new WrapPanel();
            foreach (var (key, text) in options)
            {
                bool on = key == selected;
                var b = new Border
                {
                    Background = on ? Brick : Paper, BorderBrush = Ink, BorderThickness = new Thickness(2), Padding = new Thickness(14, 7, 14, 7), Margin = new Thickness(0, 0, -2, 6),
                    Cursor = enabled ? Cursors.Hand : Cursors.Arrow, Tag = key,
                    Child = new TextBlock { Text = text, FontFamily = BodyFont, FontSize = 13, FontWeight = on ? FontWeights.Bold : FontWeights.Normal, Foreground = on ? White : enabled ? Ink : Mute },
                };
                string k = key;
                if (enabled) b.MouseLeftButtonUp += (_, _) => pick(k);
                wp.Children.Add(b);
            }
            return wp;
        }

        /// <summary>One measured value as a ruled row: name on the leading side, value on the trailing side.</summary>
        public static FrameworkElement Stat(string label, string value, Brush color = null, string sub = null)
        {
            var dp = new DockPanel();
            var v = new TextBlock { Text = value, FontFamily = HasArabic(value) ? BodyFont : Mono, FontWeight = FontWeights.Bold, FontSize = 15, Foreground = color ?? Ink, VerticalAlignment = VerticalAlignment.Center, FlowDirection = HasArabic(value) ? FlowDirection.RightToLeft : FlowDirection.LeftToRight };
            DockPanel.SetDock(v, Dock.Right); dp.Children.Add(v);
            var l = new StackPanel();
            l.Children.Add(Text(label, 13, Ink));
            if (sub != null) l.Children.Add(Text(sub, 11.5, Steel));
            dp.Children.Add(l);
            return new Border { BorderBrush = Hair, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(0, 7, 0, 7), Child = dp };
        }

        public static Border Pill(string text, Brush bg, Brush fg = null)
            => new Border { Background = bg, Padding = new Thickness(8, 2, 8, 3), Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Left, Child = new TextBlock { Text = text, FontFamily = LabelFont, FontSize = I18n.IsArabic ? 12 : 11, Foreground = fg ?? White, FontWeight = FontWeights.SemiBold } };

        public static UniformGrid Columns(int n, params UIElement[] items)
        {
            var g = new UniformGrid { Columns = n };
            foreach (var i in items) { if (i is FrameworkElement fe) fe.Margin = new Thickness(0, 0, 14, 14); g.Children.Add(i); }
            return g;
        }

        public static TextBox Input(string text = "", double width = 260, string placeholder = null)
        {
            var tb = new TextBox { Text = text, Width = width, FontFamily = Mono, FontSize = 12.5, Padding = new Thickness(8, 6, 8, 6), BorderBrush = Ink, BorderThickness = new Thickness(2), Background = White, Margin = new Thickness(0, 0, 8, 8), VerticalAlignment = VerticalAlignment.Center, FlowDirection = FlowDirection.LeftToRight, ToolTip = placeholder };
            return tb;
        }

        /// <summary>Read-only table. Columns are (header, property path, star/pixel width, mono).</summary>
        public static DataGrid Table(IEnumerable rows, params (string header, string path, double width, bool mono)[] cols)
        {
            var dg = new DataGrid
            {
                AutoGenerateColumns = false, IsReadOnly = true, HeadersVisibility = DataGridHeadersVisibility.Column, GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                HorizontalGridLinesBrush = Hair, BorderBrush = Ink, BorderThickness = new Thickness(2), Background = Paper, RowBackground = Paper, AlternatingRowBackground = RowAlt,
                SelectionMode = DataGridSelectionMode.Single, SelectionUnit = DataGridSelectionUnit.FullRow, CanUserAddRows = false, CanUserDeleteRows = false, CanUserResizeRows = false,
                RowHeaderWidth = 0, FontFamily = BodyFont, FontSize = 12.5, MinRowHeight = 30, ItemsSource = rows, MaxHeight = 420, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                EnableRowVirtualization = true,
            };
            var hs = new Style(typeof(DataGridColumnHeader));
            hs.Setters.Add(new Setter(Control.BackgroundProperty, Ink));
            hs.Setters.Add(new Setter(Control.ForegroundProperty, White));
            hs.Setters.Add(new Setter(Control.FontFamilyProperty, LabelFont));
            hs.Setters.Add(new Setter(Control.FontSizeProperty, I18n.IsArabic ? 12.5 : 11.0));
            hs.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(10, 8, 10, 8)));
            hs.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Left));
            dg.ColumnHeaderStyle = hs;
            var cs = new Style(typeof(DataGridCell));
            cs.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
            cs.Setters.Add(new Setter(Control.ForegroundProperty, Ink));
            var trig = new Trigger { Property = DataGridCell.IsSelectedProperty, Value = true };
            trig.Setters.Add(new Setter(Control.BackgroundProperty, Sel));
            trig.Setters.Add(new Setter(Control.ForegroundProperty, Ink));
            cs.Triggers.Add(trig);
            dg.CellStyle = cs;
            foreach (var (header, path, width, mono) in cols)
            {
                var es = new Style(typeof(TextBlock));
                es.Setters.Add(new Setter(FrameworkElement.MarginProperty, new Thickness(10, 6, 10, 6)));
                es.Setters.Add(new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis));
                es.Setters.Add(new Setter(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center));
                if (mono)
                {
                    es.Setters.Add(new Setter(TextBlock.FontFamilyProperty, Mono));
                    es.Setters.Add(new Setter(TextBlock.FontSizeProperty, 11.5));
                    es.Setters.Add(new Setter(FrameworkElement.FlowDirectionProperty, FlowDirection.LeftToRight));
                }
                dg.Columns.Add(new DataGridTextColumn
                {
                    Header = I18n.IsArabic ? header : header.ToUpperInvariant(), Binding = new Binding(path) { Mode = BindingMode.OneWay },
                    Width = width <= 0 ? new DataGridLength(-width <= 0 ? 1 : -width, DataGridLengthUnitType.Star) : new DataGridLength(width), ElementStyle = es,
                });
            }
            return dg;
        }

        public static FrameworkElement Empty(string text) => new Border { BorderBrush = Hair, BorderThickness = new Thickness(2), Padding = new Thickness(18), Child = Text(text, 13, Steel) };

        /// <summary>Horizontal bar used for feature importances and score meters.</summary>
        public static FrameworkElement Bar(string label, double fraction, string value, Brush color = null)
        {
            var g = new Grid { Margin = new Thickness(0, 0, 0, 6) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(210) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(64) });
            var l = MonoText(label, 11.5); l.TextWrapping = TextWrapping.NoWrap; l.TextTrimming = TextTrimming.CharacterEllipsis; l.TextAlignment = TextAlignment.Left; l.Margin = new Thickness(0, 0, 8, 0);
            g.Children.Add(l);
            var track = new Grid { Height = 14, Background = Stone, FlowDirection = FlowDirection.LeftToRight };
            track.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Math.Clamp(fraction, 0, 1), GridUnitType.Star) });
            track.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1 - Math.Clamp(fraction, 0, 1), GridUnitType.Star) });
            track.Children.Add(new Rectangle { Fill = color ?? Brick });
            Grid.SetColumn(track, 1); g.Children.Add(track);
            var v = MonoText(value, 11.5); v.TextAlignment = TextAlignment.Right; Grid.SetColumn(v, 2); g.Children.Add(v);
            return g;
        }

        public static Brush SeverityBrush(Severity s) => s switch { Severity.Critical => Red, Severity.High => Brick, Severity.Medium => Amber, Severity.Low => Steel, _ => Moss };
        public static string SeverityText(Severity s) => s switch
        {
            Severity.Critical => L("CRITICAL", "حرج"), Severity.High => L("HIGH", "عالٍ"), Severity.Medium => L("MEDIUM", "متوسط"), Severity.Low => L("LOW", "منخفض"), _ => L("INFO", "معلومة"),
        };
        public static string KindText(EventKind k) => k switch
        {
            EventKind.Firewall => L("Firewall", "الجدار الناري"), EventKind.Antivirus => L("Antivirus", "مكافح الفيروسات"), EventKind.Ransomware => L("Ransomware", "الفدية"),
            EventKind.Network => L("Network AI", "ذكاء الشبكة"), EventKind.Ai => L("Auto-pilot", "الطيار الآلي"), EventKind.Persistence => L("Persistence", "بدء التشغيل"), _ => L("System", "النظام"),
        };
    }
}
