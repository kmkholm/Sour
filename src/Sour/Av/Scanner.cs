using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Sour.Core;

namespace Sour.Av
{
    public enum Verdict { Clean, Suspicious, Malicious, Error, Skipped }

    public sealed class Reason
    {
        public string Code, En, Ar; public int Weight;
        public string Text => I18n.T(En, Ar);
        public Reason() { }
        public Reason(string code, int weight, string en, string ar) { Code = code; Weight = weight; En = en; Ar = ar; }
    }

    public sealed class ScanResult
    {
        public string Path; public string Kind; public long Size; public string Sha256;
        public Verdict Verdict; public int Score;
        public List<Reason> Reasons = new List<Reason>();
        public double MlProb = -1;
        public List<(string name, double contribution, double value)> MlTop;
        public string Signer; public bool SignedValid;
        public string Error; public double Ms;
        public string Threat => Reasons.OrderByDescending(r => r.Weight).Select(r => r.Code).FirstOrDefault() ?? "";
        public string Summary => string.Join(" · ", Reasons.OrderByDescending(r => r.Weight).Take(4).Select(r => r.Text));
    }

    /// <summary>Second opinion from whichever antimalware provider is registered with AMSI (normally Microsoft Defender).</summary>
    public static class Amsi
    {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)] static extern int AmsiInitialize(string appName, out IntPtr ctx);
        [DllImport("amsi.dll")] static extern void AmsiUninitialize(IntPtr ctx);
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)] static extern int AmsiScanBuffer(IntPtr ctx, byte[] buffer, uint length, string contentName, IntPtr session, out int result);

        static IntPtr _ctx; static bool _failed; static readonly object Gate = new object();
        public static bool Available { get { Ensure(); return _ctx != IntPtr.Zero; } }

        static void Ensure()
        {
            if (_ctx != IntPtr.Zero || _failed) return;
            lock (Gate)
            {
                if (_ctx != IntPtr.Zero || _failed) return;
                try { if (AmsiInitialize("Sour", out _ctx) != 0) { _ctx = IntPtr.Zero; _failed = true; } }
                catch { _failed = true; }
            }
        }

        /// <summary>true = the provider says malware; false = clean/unknown; null = AMSI unavailable.</summary>
        public static bool? IsMalware(byte[] data, string name)
        {
            Ensure();
            if (_ctx == IntPtr.Zero || data.Length == 0) return null;
            try
            {
                int hr = AmsiScanBuffer(_ctx, data, (uint)data.Length, name ?? "buffer", IntPtr.Zero, out int result);
                if (hr != 0) return null;
                return result >= 32768;      // AMSI_RESULT_DETECTED
            }
            catch { return null; }
        }
    }

    /// <summary>User-maintained and feed-supplied SHA-256 block list.</summary>
    public static class HashDb
    {
        static HashSet<string> _set; static readonly object Gate = new object();
        public static string FeedFile => Path.Combine(Paths.Root, "hashes_feed.txt");

        public static HashSet<string> Set
        {
            get
            {
                lock (Gate)
                {
                    if (_set != null) return _set;
                    var s = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (string f in new[] { Paths.HashDbFile, FeedFile })
                    {
                        try
                        {
                            if (!File.Exists(f)) continue;
                            foreach (string line in File.ReadLines(f))
                            {
                                string t = line.Trim();
                                if (t.Length < 64 || t[0] == '#') continue;
                                string h = t.Substring(0, 64);
                                if (h.All(Uri.IsHexDigit)) s.Add(h);
                            }
                        }
                        catch { }
                    }
                    return _set = s;
                }
            }
        }
        public static void Reload() { lock (Gate) _set = null; }
        public static void AddUser(string sha256, string note)
        {
            File.AppendAllText(Paths.HashDbFile, sha256.ToLowerInvariant() + " " + note + Environment.NewLine);
            Reload();
        }
    }

    /// <summary>
    /// The scan pipeline. Layers, in order: hash block list → file-type detection → Authenticode / catalog trust →
    /// signature rules → structural heuristics → ML model (PE) → AMSI second opinion → verdict fusion.
    /// Every point added to the score is recorded as a Reason, so each verdict can be explained.
    /// </summary>
    public sealed class Scanner
    {
        public static readonly Scanner Instance = new Scanner();

        static readonly HashSet<string> ScriptExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".php", ".phtml", ".asp", ".aspx", ".ashx", ".jsp", ".sh", ".sct" };
        static readonly HashSet<string> TextExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".xml", ".rels", ".txt", ".md", ".html", ".htm", ".json", ".csv", ".rtf", ".tex", ".log", ".yml", ".yaml", ".srt" };
        static readonly HashSet<string> ExeExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".pif", ".msi", ".drv", ".efi" };
        static readonly HashSet<string> ZipExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".zip", ".jar", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".apk", ".nupkg", ".xlam", ".dotm", ".war" };
        static readonly HashSet<string> DisguiseExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".mp3", ".mp4", ".avi", ".csv", ".rtf", ".html" };
        static readonly string[] SystemNames = { "svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "winlogon.exe", "services.exe", "smss.exe",
            "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "rundll32.exe", "wininit.exe", "dllhost.exe", "ctfmon.exe", "sihost.exe" };
        static readonly Dictionary<string, string> PackerSections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["upx0"] = "UPX", ["upx1"] = "UPX", ["upx2"] = "UPX", [".aspack"] = "ASPack", [".adata"] = "ASPack", [".mpress1"] = "MPRESS", [".mpress2"] = "MPRESS",
            [".themida"] = "Themida", [".vmp0"] = "VMProtect", [".vmp1"] = "VMProtect", [".vmp2"] = "VMProtect", [".enigma1"] = "Enigma", [".enigma2"] = "Enigma",
            [".petite"] = "Petite", ["pec2"] = "PECompact", ["pecompact2"] = "PECompact", [".nsp0"] = "NsPack", [".nsp1"] = "NsPack", [".perplex"] = "Perplex",
            [".winlice"] = "WinLicense", [".boom"] = "Boomerang", [".taz"] = "PESpin", [".yp"] = "Y0da", [".packed"] = "RLPack", ["fsg!"] = "FSG",
        };

        readonly ConcurrentDictionary<string, (long stamp, ScanResult res)> _cache = new ConcurrentDictionary<string, (long, ScanResult)>(StringComparer.OrdinalIgnoreCase);
        public long FilesScanned, Detections;

        public static bool IsExcluded(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            foreach (string ex in Settings.Current.AvExclusions)
                if (!string.IsNullOrWhiteSpace(ex) && path.StartsWith(ex.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;
            // Sour's own data (encoded rules, quarantine) and other AV engines' signature stores
            if (path.StartsWith(Paths.Root, StringComparison.OrdinalIgnoreCase)) return true;
            // Scratch folders of a self-test or snapshot run belong to that other instance.
            // (The test instance itself has OverrideRoot set and must still scan its own scratch files.)
            if (Paths.OverrideRoot == null && (path.IndexOf("\\sour_selftest_", StringComparison.OrdinalIgnoreCase) >= 0 || path.IndexOf("\\sour_snap_", StringComparison.OrdinalIgnoreCase) >= 0)) return true;
            if (path.StartsWith(Paths.DataDir, StringComparison.OrdinalIgnoreCase)) return true;
            if (path.IndexOf("\\Microsoft\\Windows Defender\\", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        public ScanResult ScanFile(string path, bool useCache = true)
        {
            var sw = Stopwatch.StartNew();
            var r = new ScanResult { Path = path };
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) { r.Verdict = Verdict.Error; r.Error = "not found"; return r; }
                r.Size = fi.Length;
                if (IsExcluded(path)) { r.Verdict = Verdict.Skipped; r.Error = "excluded"; return r; }
                long stamp = fi.LastWriteTimeUtc.Ticks ^ fi.Length;
                if (useCache && _cache.TryGetValue(path, out var c) && c.stamp == stamp) return c.res;

                if (fi.Length > Settings.Current.AvMaxFileMb * 1024L * 1024L)
                {
                    r.Sha256 = Util.Sha256(path);
                    if (HashDb.Set.Contains(r.Sha256)) { r.Reasons.Add(new Reason("Hash.Blocklist", 100, "SHA-256 is on the block list", "بصمة الملف SHA-256 موجودة في قائمة الحظر")); Finish(r); }
                    else { r.Verdict = Verdict.Skipped; r.Error = "larger than the size limit (hash checked only)"; }
                    return r;
                }
                byte[] data;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan))
                {
                    data = new byte[fs.Length];
                    int off = 0, n;
                    while (off < data.Length && (n = fs.Read(data, off, data.Length - off)) > 0) off += n;
                }
                Analyze(r, data, path, 0);
                if (_cache.Count > 200000) _cache.Clear();
                _cache[path] = (stamp, r);
            }
            catch (UnauthorizedAccessException) { r.Verdict = Verdict.Skipped; r.Error = "access denied"; }
            catch (IOException ex) { r.Verdict = Verdict.Skipped; r.Error = ex.Message; }
            catch (Exception ex) { r.Verdict = Verdict.Error; r.Error = ex.Message; }
            finally
            {
                r.Ms = sw.Elapsed.TotalMilliseconds;
                System.Threading.Interlocked.Increment(ref FilesScanned);
                if (r.Verdict == Verdict.Malicious || r.Verdict == Verdict.Suspicious) System.Threading.Interlocked.Increment(ref Detections);
            }
            return r;
        }

        /// <summary>Scans bytes that are not (or not yet) a file on disk. Trust checks are skipped.</summary>
        public ScanResult ScanBuffer(byte[] data, string name)
        {
            var r = new ScanResult { Path = name, Size = data.Length };
            try { Analyze(r, data, null, 0); } catch (Exception ex) { r.Verdict = Verdict.Error; r.Error = ex.Message; }
            return r;
        }

        static string DetectKind(byte[] d, string ext)
        {
            if (d.Length >= 2 && d[0] == 'M' && d[1] == 'Z') return "pe";
            if (d.Length >= 4 && d[0] == 0x4C && d[1] == 0 && d[2] == 0 && d[3] == 0 && ext == ".lnk") return "lnk";
            if (ScriptExt.Contains(ext)) return "script";
            if (d.Length >= 4 && d[0] == 'P' && d[1] == 'K' && d[2] == 3 && d[3] == 4) return "zip";
            if (d.Length >= 2 && d[0] == '#' && d[1] == '!') return "script";
            if (TextExt.Contains(ext)) return "text";      // prose and markup: may mention malware by name without being malware
            return "other";
        }

        void Analyze(ScanResult r, byte[] data, string diskPath, int depth)
        {
            string name = System.IO.Path.GetFileName(r.Path ?? "");
            string ext = System.IO.Path.GetExtension(name).ToLowerInvariant();
            r.Sha256 = Util.Sha256(data);
            r.Kind = DetectKind(data, ext);
            var s = Settings.Current;

            if (HashDb.Set.Contains(r.Sha256))
                r.Reasons.Add(new Reason("Hash.Blocklist", 100, "SHA-256 is on the block list", "بصمة الملف SHA-256 موجودة في قائمة الحظر"));

            // ---- trust
            TrustInfo trust = null;
            if (diskPath != null && (r.Kind == "pe" || ext == ".ps1" || ext == ".msi" || ext == ".vbs" || ext == ".js"))
            {
                trust = Trust.Check(diskPath);
                r.SignedValid = trust.Valid; r.Signer = trust.Describe();
            }
            bool signed = trust != null && trust.Valid;
            bool microsoft = trust != null && trust.IsMicrosoft;

            PeFile pe = r.Kind == "pe" ? PeFile.Parse(data) : null;

            // ---- signature rules
            var hits = RuleEngine.Instance.Scan(data, r.Kind, ext, signed, pe);
            int ruleScore = 0;
            foreach (var h in hits.OrderByDescending(h => h.Rule.score))
            {
                r.Reasons.Add(new Reason(h.Rule.id, h.Rule.score, h.Rule.en + (string.IsNullOrEmpty(h.Rule.mitre) ? "" : $" [{h.Rule.mitre}]"), h.Rule.ar + (string.IsNullOrEmpty(h.Rule.mitre) ? "" : $" [{h.Rule.mitre}]")));
                ruleScore = ruleScore == 0 ? h.Rule.score : Math.Min(100, ruleScore + 10);
            }

            // ---- heuristics
            int heur = 0;
            void H(string code, int w, string en, string ar) { r.Reasons.Add(new Reason(code, w, en, ar)); heur += w; }

            if (name.Contains('\u202E')) H("Heur.RtlOverride", 45, "File name uses the right-to-left override trick to hide its real extension", "اسم الملف يستخدم خدعة عكس الاتجاه لإخفاء امتداده الحقيقي");
            {
                string stem = System.IO.Path.GetFileNameWithoutExtension(name);
                string inner = System.IO.Path.GetExtension(stem).ToLowerInvariant();
                if ((ExeExt.Contains(ext) || ScriptExt.Contains(ext) || ext == ".lnk") && DisguiseExt.Contains(inner))
                    H("Heur.DoubleExtension", 40, $"Double extension ({inner}{ext}) - a program posing as a document", $"امتداد مزدوج ({inner}{ext}) - برنامج يتنكّر كمستند");
            }

            if (pe != null && pe.Valid)
            {
                if (!ExeExt.Contains(ext) && DisguiseExt.Contains(ext))
                    H("Heur.DisguisedExecutable", 35, $"Windows executable stored with a {ext} extension", $"ملف تنفيذي محفوظ بامتداد {ext}");

                if (trust != null && trust.Embedded && !trust.Valid)
                {
                    // distinguish "the bytes were changed after signing" from "the chain cannot be validated"
                    if (trust.Status == 0x80096010)
                        H("Heur.ModifiedAfterSigning", 40, $"File was modified after it was signed by {trust.Publisher} (hash mismatch)", $"عُدِّل الملف بعد توقيعه من {trust.Publisher} (عدم تطابق البصمة)");
                    else if (trust.Status == 0x800B0101)
                        H("Heur.ExpiredSignature", 5, "Signing certificate expired and the signature carries no valid timestamp", "شهادة التوقيع منتهية ولا يحمل التوقيع ختماً زمنياً صالحاً");
                    else if (trust.Status == 0x800B0109 || trust.Status == 0x800B010A)
                        H("Heur.UntrustedSigner", 10, $"Signed by {trust.Publisher}, but the certificate chain is not trusted by Windows", $"موقَّع من {trust.Publisher} لكن سلسلة الشهادة غير موثوقة لدى ويندوز");
                    else if (trust.Status == 0x800B010C || trust.Status == 0x80092010)
                        H("Heur.RevokedSignature", 45, "The signing certificate has been revoked", "شهادة التوقيع ملغاة");
                    else
                        H("Heur.InvalidSignature", 15, $"Digital signature does not verify (0x{trust.Status:X8})", $"التوقيع الرقمي لا يتحقق (0x{trust.Status:X8})");
                }

                // masquerading as a Windows system process
                string lower = name.ToLowerInvariant();
                string dir = diskPath == null ? "" : (System.IO.Path.GetDirectoryName(diskPath) ?? "").ToLowerInvariant();
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
                if (!microsoft && diskPath != null)
                {
                    if (SystemNames.Contains(lower) && !dir.StartsWith(win))
                        H("Heur.SystemNameWrongPlace", 50, $"Named like the Windows component {lower} but stored outside the Windows folder and not signed by Microsoft", $"يحمل اسم مكوّن ويندوز {lower} لكنه خارج مجلد ويندوز وغير موقَّع من مايكروسوفت");
                    else if (!SystemNames.Contains(lower) && SystemNames.Any(sn => Math.Abs(sn.Length - lower.Length) <= 1 && Levenshtein(sn, lower) == 1))
                        H("Heur.LookalikeName", 40, $"Name imitates a Windows component ({lower})", $"اسم يقلّد مكوّن ويندوز ({lower})");
                }

                if (!signed)
                {
                    var packers = pe.Sections.Select(x => PackerSections.TryGetValue(x.Name, out string p) ? p : null).Where(p => p != null).Distinct().ToList();
                    if (packers.Count > 0) H("Heur.Packed", 25, "Packed/protected with " + string.Join(", ", packers), "مضغوط/محمي بواسطة " + string.Join(", ", packers));

                    string entry = "";
                    foreach (var x in pe.Sections) if (pe.Contains(x, pe.AddressOfEntryPoint)) entry = x.Name;
                    var es = pe.Sections.FirstOrDefault(x => x.Name == entry && pe.Contains(x, pe.AddressOfEntryPoint));
                    if (es != null && es.Write && es.Exec) H("Heur.WritableEntry", 15, "Entry-point section is both writable and executable (self-modifying code)", "قسم نقطة الدخول قابل للكتابة والتنفيذ معاً (شيفرة تعدّل نفسها)");
                    if (es != null && es.Entropy > 7.2 && packers.Count == 0) H("Heur.EncryptedCode", 15, $"Code section is encrypted or compressed (entropy {es.Entropy:0.00})", $"قسم الشيفرة مشفّر أو مضغوط (إنتروبيا {es.Entropy:0.00})");
                    int nImp = pe.Imports.Sum(kv => kv.Value.Count);
                    if (!pe.IsDotNet && !pe.IsDll && nImp <= 3 && pe.Sections.Count > 0) H("Heur.FewImports", 15, $"Almost no imported functions ({nImp}) - imports are resolved at run time", $"لا يستورد دوالّ تقريباً ({nImp}) - يحلّ الاستيرادات وقت التشغيل");
                    if (pe.TimeDateStamp != 0 && DateTimeOffset.FromUnixTimeSeconds(pe.TimeDateStamp) > DateTimeOffset.UtcNow.AddDays(2))
                        H("Heur.FutureTimestamp", 5, "Build timestamp lies in the future", "تاريخ البناء في المستقبل");
                    if (diskPath != null)
                    {
                        string temp = System.IO.Path.GetTempPath().TrimEnd('\\').ToLowerInvariant();
                        string pub = (Environment.GetEnvironmentVariable("PUBLIC") ?? "c:\\users\\public").ToLowerInvariant();
                        if (dir.StartsWith(temp) || dir.StartsWith(pub) || dir.Contains("\\$recycle.bin"))
                            H("Heur.UnsignedInTemp", 8, "Unsigned program in a temporary/public folder", "برنامج غير موقَّع في مجلد مؤقت أو عام");
                        try { var at = File.GetAttributes(diskPath); if ((at & FileAttributes.Hidden) != 0 && (at & FileAttributes.System) != 0 && !dir.StartsWith(win)) H("Heur.HiddenSystem", 10, "Hidden + system attributes on a program outside Windows", "برنامج خارج ويندوز يحمل سمتَي مخفي ونظام"); } catch { }
                    }
                }
            }
            else if (r.Kind == "pe" && ExeExt.Contains(ext))
                H("Heur.CorruptPe", 10, "Starts like a Windows executable but its headers are malformed", "يبدأ كملف تنفيذي لكن ترويساته تالفة");

            if (r.Kind == "script" || r.Kind == "lnk") heur += ScriptHeuristics(r, data);
            heur = Math.Min(heur, 75);

            // ---- ML
            int ml = 0;
            if (s.AvUseMl && pe != null && pe.Valid && data.Length >= 1024 && MlModel.Instance.Loaded && !microsoft)
            {
                var m = MlModel.Instance;
                var sc = m.Explain(PeFeatures.Extract(pe));
                r.MlProb = sc.Prob; r.MlTop = sc.Top;
                string why = sc.Top.Count == 0 ? "" : " ← " + string.Join(", ", sc.Top.Take(4).Select(t => t.name));
                if (sc.Prob >= m.ThresholdMalicious)
                {
                    ml = signed ? 30 : 85 + (int)Math.Round(10 * (sc.Prob - m.ThresholdMalicious) / Math.Max(1 - m.ThresholdMalicious, 1e-6));
                    r.Reasons.Add(new Reason("ML.Malicious", ml, $"AI model: {sc.Prob:P1} malicious{(signed ? " (capped: file is validly signed)" : "")}{why}", $"نموذج الذكاء الاصطناعي: احتمال الخبث {sc.Prob:P1}{(signed ? " (مخفَّض: الملف موقَّع توقيعاً صحيحاً)" : "")}{why}"));
                }
                else if (sc.Prob >= m.ThresholdSuspicious && !signed)
                {
                    ml = 55;
                    r.Reasons.Add(new Reason("ML.Suspicious", ml, $"AI model: {sc.Prob:P1} malicious (suspicious band){why}", $"نموذج الذكاء الاصطناعي: احتمال الخبث {sc.Prob:P1} (نطاق الاشتباه){why}"));
                }
            }

            // ---- AMSI second opinion: scripts always, other content when not validly signed
            if (s.AvUseAmsi && !microsoft && data.Length <= 32 * 1024 * 1024 && (r.Kind == "script" || r.Kind == "lnk" || !signed))
            {
                if (Amsi.IsMalware(data, r.Path) == true)
                    r.Reasons.Add(new Reason("AMSI.Detected", 100, "The system antimalware provider (AMSI) flags this content", "مزوّد الحماية في النظام (AMSI) يصنّف هذا المحتوى خبيثاً"));
            }

            // ---- archives
            if (s.AvScanArchives && r.Kind == "zip" && depth < 2) ScanZip(r, data, depth);

            // ---- fusion
            int top = r.Reasons.Count == 0 ? 0 : r.Reasons.Where(x => x.Code.StartsWith("Hash.") || x.Code.StartsWith("AMSI.") || x.Code.StartsWith("Archive.")).Select(x => x.Weight).DefaultIfEmpty(0).Max();
            int score = Math.Max(Math.Max(ruleScore, ml), Math.Max(heur, top));
            if (ml >= 55 && heur >= 25) score += 15;
            if (ruleScore >= 30 && ml >= 55) score += 15;
            if (ruleScore >= 40 && heur >= 25) score += 10;
            r.Score = Math.Min(100, score);
            Finish(r);
        }

        static void Finish(ScanResult r)
        {
            if (r.Score == 0 && r.Reasons.Count > 0) r.Score = Math.Min(100, r.Reasons.Max(x => x.Weight));
            r.Verdict = r.Score >= 80 ? Verdict.Malicious : r.Score >= 40 ? Verdict.Suspicious : Verdict.Clean;
        }

        static int ScriptHeuristics(ScanResult r, byte[] data)
        {
            int add = 0, run = 0, maxRun = 0, ticks = 0, lineLen = 0, maxLine = 0;
            int n = Math.Min(data.Length, 4 * 1024 * 1024);
            for (int i = 0; i < n; i++)
            {
                byte b = data[i];
                bool b64 = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=';
                if (b64) { run++; if (run > maxRun) maxRun = run; } else run = 0;
                if (b == '`' || b == '^') ticks++;
                if (b == '\n') { if (lineLen > maxLine) maxLine = lineLen; lineLen = 0; } else lineLen++;
            }
            if (lineLen > maxLine) maxLine = lineLen;
            string text = Encoding.Latin1.GetString(data, 0, n).ToLowerInvariant();
            int charCodes = Count(text, "[char]") + Count(text, "chr(") + Count(text, "chrw(") + Count(text, "fromcharcode");
            if (maxRun >= 1500) { r.Reasons.Add(new Reason("Heur.Script.Base64Blob", 25, $"Embeds a {maxRun}-character Base64 blob", $"يتضمن كتلة Base64 بطول {maxRun} حرفاً")); add += 25; }
            if (charCodes >= 20) { r.Reasons.Add(new Reason("Heur.Script.CharCodes", 25, $"Builds its commands from character codes ({charCodes} conversions)", $"يبني أوامره من رموز الحروف ({charCodes} تحويلاً)")); add += 25; }
            if (n > 400 && ticks / (double)n > 0.03) { r.Reasons.Add(new Reason("Heur.Script.EscapeNoise", 20, "Heavy use of escape characters to break up keywords", "إفراط في رموز الهروب لتقطيع الكلمات المفتاحية")); add += 20; }
            if (maxLine > 20000) { r.Reasons.Add(new Reason("Heur.Script.GiantLine", 10, $"One line of {maxLine} characters", $"سطر واحد بطول {maxLine} حرفاً")); add += 10; }
            return add;
        }

        static int Count(string hay, string needle)
        {
            int c = 0, i = 0;
            while ((i = hay.IndexOf(needle, i, StringComparison.Ordinal)) >= 0) { c++; i += needle.Length; }
            return c;
        }

        void ScanZip(ScanResult r, byte[] data, int depth)
        {
            try
            {
                using var za = new ZipArchive(new MemoryStream(data, false), ZipArchiveMode.Read);
                int count = 0; long total = 0; bool encrypted = false; var exeNames = new List<string>();
                ScanResult worst = null;
                foreach (var e in za.Entries)
                {
                    if (++count > 400) break;
                    string eext = System.IO.Path.GetExtension(e.Name).ToLowerInvariant();
                    if (ExeExt.Contains(eext) || ScriptExt.Contains(eext) || eext == ".lnk") exeNames.Add(e.Name);
                    if (e.Length == 0 || e.Length > 64L * 1024 * 1024) continue;
                    total += e.Length;
                    if (total > 512L * 1024 * 1024) break;      // decompression-bomb guard
                    byte[] buf;
                    try
                    {
                        using var es = e.Open();
                        using var ms = new MemoryStream((int)e.Length);
                        es.CopyTo(ms); buf = ms.ToArray();
                    }
                    catch (InvalidDataException) { encrypted = true; continue; }
                    catch { continue; }
                    var sub = new ScanResult { Path = r.Path + "!" + e.FullName, Size = buf.Length };
                    Analyze(sub, buf, null, depth + 1);
                    if (sub.Score > (worst?.Score ?? 0)) worst = sub;
                }
                if (worst != null && worst.Score >= 40)
                {
                    string inner = worst.Path.Substring(worst.Path.IndexOf('!') + 1);
                    r.Reasons.Add(new Reason("Archive." + worst.Threat, worst.Score, $"Archive member {inner}: {worst.Reasons.OrderByDescending(x => x.Weight).First().En}", $"داخل الأرشيف {inner}: {worst.Reasons.OrderByDescending(x => x.Weight).First().Ar}"));
                }
                if (encrypted && exeNames.Count > 0)
                    r.Reasons.Add(new Reason("Archive.EncryptedExecutable", 45, "Password-protected archive containing a program (" + exeNames[0] + ") - a common way to slip past scanners", "أرشيف محمي بكلمة مرور يحتوي برنامجاً (" + exeNames[0] + ") - أسلوب شائع لتجاوز الفحص"));
            }
            catch { }
        }

        static int Levenshtein(string a, string b)
        {
            var d = new int[a.Length + 1, b.Length + 1];
            for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
            for (int j = 0; j <= b.Length; j++) d[0, j] = j;
            for (int i = 1; i <= a.Length; i++)
                for (int j = 1; j <= b.Length; j++)
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1));
            return d[a.Length, b.Length];
        }

        // ---------------- folder scans
        public sealed class Progress { public long Files, Detections; public string Current; public bool Done; public double Seconds; }

        static readonly EnumerationOptions Walk = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint };

        public static IEnumerable<string> QuickScanRoots()
        {
            string up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var roots = new List<string>
            {
                System.IO.Path.Combine(up, "Downloads"), Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                System.IO.Path.GetTempPath(), Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            };
            return roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>Scans files/folders. Quick mode looks only at programs, scripts, shortcuts and archives.</summary>
        public List<ScanResult> ScanPaths(IEnumerable<string> paths, bool allFiles, Action<Progress> report, System.Threading.CancellationToken ct)
        {
            var found = new List<ScanResult>();
            var p = new Progress();
            var sw = Stopwatch.StartNew();
            var last = DateTime.MinValue;
            foreach (string root in paths)
            {
                IEnumerable<string> files;
                if (File.Exists(root)) files = new[] { root };
                else if (Directory.Exists(root)) { try { files = Directory.EnumerateFiles(root, "*", Walk); } catch { continue; } }
                else continue;
                foreach (string f in files)
                {
                    if (ct.IsCancellationRequested) break;
                    string ext = System.IO.Path.GetExtension(f);
                    if (!allFiles && !(ExeExt.Contains(ext) || ScriptExt.Contains(ext) || ZipExt.Contains(ext) || string.Equals(ext, ".lnk", StringComparison.OrdinalIgnoreCase) || string.Equals(ext, ".inf", StringComparison.OrdinalIgnoreCase))) continue;
                    var r = ScanFile(f);
                    p.Files++; p.Current = f;
                    if (r.Verdict == Verdict.Malicious || r.Verdict == Verdict.Suspicious) { found.Add(r); p.Detections++; }
                    if ((DateTime.Now - last).TotalMilliseconds > 200) { last = DateTime.Now; p.Seconds = sw.Elapsed.TotalSeconds; report?.Invoke(p); }
                }
                if (ct.IsCancellationRequested) break;
            }
            p.Done = true; p.Seconds = sw.Elapsed.TotalSeconds; report?.Invoke(p);
            return found;
        }
    }
}
