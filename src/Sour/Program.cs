using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using Sour.Av;
using Sour.Core;
using Sour.Fw;

namespace Sour
{
    public static class Program
    {
        [DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);

        [STAThread]
        public static int Main(string[] args)
        {
            if (args.Length > 0 && args[0].StartsWith("--") && args[0] != "--minimized" && args[0] != "--scan-ui")
            {
                AttachConsole(-1);
                try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
                try { return Cli(args); }
                catch (Exception ex) { Console.WriteLine("FATAL " + ex); return 99; }
            }
            return Ui.AppHost.Run(args);
        }

        static int Cli(string[] a)
        {
            switch (a[0])
            {
                case "--selftest":
                    return SelfTest.Run(a.Skip(1).ToArray());

                case "--features":
                {
                    // one JSON line per file: used by tools/verify_features.py to compare against the training extractor
                    foreach (string f in a.Skip(1))
                    {
                        var pe = PeFile.Parse(File.ReadAllBytes(f));
                        Console.WriteLine(JsonSerializer.Serialize(new { file = f, valid = pe.Valid, x = pe.Valid ? PeFeatures.Extract(pe) : null }));
                    }
                    return 0;
                }

                case "--scan":
                {
                    bool all = a.Contains("--all");
                    var paths = a.Skip(1).Where(x => !x.StartsWith("--")).ToList();
                    if (paths.Count == 0) paths = Scanner.QuickScanRoots().ToList();
                    Settings.Current.AvUseAmsi = !a.Contains("--no-amsi") && Settings.Current.AvUseAmsi;
                    var found = Scanner.Instance.ScanPaths(paths, all, null, CancellationToken.None);
                    foreach (var r in found)
                    {
                        Console.WriteLine($"[{r.Verdict} {r.Score}] {r.Path}");
                        foreach (var why in r.Reasons.OrderByDescending(x => x.Weight)) Console.WriteLine($"      {why.Weight,3}  {why.Code}: {why.En}");
                    }
                    Console.WriteLine($"scanned {Scanner.Instance.FilesScanned} files, {found.Count} flagged");
                    return found.Any(r => r.Verdict == Verdict.Malicious) ? 2 : found.Count > 0 ? 1 : 0;
                }

                case "--fp-test":
                {
                    // false-positive measurement on a folder of presumed-clean software
                    string dir = a[1]; int max = a.Length > 2 ? int.Parse(a[2]) : 500;
                    Settings.Current.AvUseAmsi = false;
                    var opt = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true };
                    int n = 0, mal = 0, sus = 0, signed = 0, mlRun = 0; double ms = 0;
                    var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl" };
                    foreach (string f in Directory.EnumerateFiles(dir, "*", opt).Where(f => exts.Contains(Path.GetExtension(f))))
                    {
                        if (n >= max) break;
                        var r = Scanner.Instance.ScanFile(f, false);
                        if (r.Verdict == Verdict.Skipped || r.Verdict == Verdict.Error) continue;
                        n++; ms += r.Ms; if (r.SignedValid) signed++; if (r.MlProb >= 0) mlRun++;
                        if (r.Verdict == Verdict.Malicious) mal++; else if (r.Verdict == Verdict.Suspicious) sus++; else continue;
                        Console.WriteLine($"[{r.Verdict} {r.Score}] ml={r.MlProb:0.000} signer={r.Signer} {f}");
                        foreach (var why in r.Reasons.OrderByDescending(x => x.Weight).Take(3)) Console.WriteLine($"      {why.Weight,3}  {why.Code}: {why.En}");
                    }
                    Console.WriteLine($"FP-TEST dir={dir} files={n} signed={signed} ml_scored={mlRun} malicious={mal} suspicious={sus} avg_ms={(n == 0 ? 0 : ms / n):0.0}");
                    return 0;
                }

                case "--fw-status":
                {
                    Console.WriteLine("admin: " + Util.IsAdmin());
                    Console.WriteLine("mode: " + Settings.Current.FirewallMode);
                    var st = FirewallEngine.LiveState();
                    Console.WriteLine(st.ok ? $"installed filters: {st.count}" : "engine: " + st.error);
                    foreach (var f in FirewallEngine.BuildSpecs(Settings.Current, RuleStore.Current, DateTime.Now)) Console.WriteLine("  " + f);
                    return 0;
                }

                case "--fw-apply": { var r = FirewallEngine.Apply(); Console.WriteLine(r); return r.Ok ? 0 : 1; }

                case "--fw-off":
                {
                    // emergency switch: remove every Sour filter and set the mode to Off
                    Settings.Current.FirewallMode = FwMode.Off; Settings.Save();
                    var r = FirewallEngine.RemoveAll();
                    Console.WriteLine(r.Ok ? $"removed {r.Removed} filters; firewall off" : "failed: " + r.Error);
                    return r.Ok ? 0 : 1;
                }

                case "--trust":
                    foreach (string f in a.Skip(1))
                    {
                        var t = Trust.Check(f);
                        Console.WriteLine($"valid={t.Valid} embedded={t.Embedded} catalog={t.Catalog} status=0x{t.Status:X8} publisher={t.Publisher} | {f}");
                    }
                    return 0;

                case "--rule-encode":
                    Console.WriteLine(RuleEngine.Encode(string.Join(" ", a.Skip(1))));
                    return 0;

                case "--amsi-test":
                {
                    // Microsoft's documented AMSI test string, assembled at run time
                    string sample = "AMSI Test Sample: " + "7e72c3ce-861b-4339-" + "8740-0ac1484c1386";
                    Console.WriteLine("amsi available: " + Amsi.Available);
                    Console.WriteLine("test sample detected: " + Amsi.IsMalware(Encoding.Unicode.GetBytes(sample), "sour-amsi-test"));
                    Console.WriteLine("benign text detected: " + Amsi.IsMalware(Encoding.Unicode.GetBytes("hello world, this is a harmless sentence"), "sour-amsi-benign"));
                    return 0;
                }

                case "--snap":
                    return Ui.AppHost.Snap(a.Length > 1 ? a[1] : Path.Combine(Path.GetTempPath(), "sour_snap"));

                default:
                    Console.WriteLine("Sour options: --selftest | --scan [paths] [--all] | --fp-test <dir> [n] | --fw-status | --fw-apply | --fw-off | --features <file> | --rule-encode <text> | --amsi-test | --snap <dir>");
                    return 64;
            }
        }
    }
}
