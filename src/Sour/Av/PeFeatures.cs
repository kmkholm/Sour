using System;
using System.Collections.Generic;
using System.Linq;

namespace Sour.Av
{
    /// <summary>
    /// The 193-dimensional static feature vector of the Sour ML detector.
    /// MUST stay in lock-step with ml/featspec.py (same order, same definitions);
    /// tools/verify_features.py compares both implementations on real files.
    /// </summary>
    public static class PeFeatures
    {
        static readonly HashSet<string> StdSections = new HashSet<string>(StringComparer.Ordinal)
        {
            ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".edata", ".tls", ".bss", ".xdata", "CODE", "DATA", "BSS",
            ".didat", ".CRT", ".gfids", ".00cfg", ".debug", "INIT", "PAGE", ".orpc", ".sdata", ".ndata",
        };
        static readonly (string name, ushort bit)[] CoffFlags =
        {
            ("RELOCS_STRIPPED", 0x0001), ("EXECUTABLE_IMAGE", 0x0002), ("LINE_NUMS_STRIPPED", 0x0004), ("LOCAL_SYMS_STRIPPED", 0x0008),
            ("LARGE_ADDRESS_AWARE", 0x0020), ("32BIT_MACHINE", 0x0100), ("DEBUG_STRIPPED", 0x0200), ("SYSTEM", 0x1000), ("DLL", 0x2000),
        };
        static readonly (string name, ushort bit)[] DllFlags =
        {
            ("HIGH_ENTROPY_VA", 0x0020), ("DYNAMIC_BASE", 0x0040), ("FORCE_INTEGRITY", 0x0080), ("NX_COMPAT", 0x0100), ("NO_ISOLATION", 0x0200),
            ("NO_SEH", 0x0400), ("NO_BIND", 0x0800), ("APPCONTAINER", 0x1000), ("WDM_DRIVER", 0x2000), ("GUARD_CF", 0x4000), ("TERMINAL_SERVER_AWARE", 0x8000),
        };
        static readonly string[] OptNum = { "major_image_version", "minor_image_version", "major_linker_version", "minor_linker_version",
            "major_operating_system_version", "minor_operating_system_version", "major_subsystem_version", "minor_subsystem_version" };
        static readonly string[] OptLog = { "sizeof_code", "sizeof_headers", "sizeof_image", "sizeof_initialized_data", "sizeof_uninitialized_data",
            "sizeof_stack_reserve", "sizeof_stack_commit", "sizeof_heap_reserve", "sizeof_heap_commit", "address_of_entrypoint", "base_of_code",
            "image_base", "section_alignment" };
        public static readonly string[] ImportDlls = { "kernel32", "user32", "advapi32", "ntdll", "wininet", "winhttp", "ws2_32", "wsock32", "urlmon",
            "shell32", "crypt32", "mscoree", "msvbvm60", "psapi", "shlwapi", "ole32", "gdi32", "netapi32", "iphlpapi", "wtsapi32", "dnsapi", "bcrypt",
            "msvcrt", "vcruntime140" };
        public static readonly string[] ImportApis = { "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory",
            "ReadProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "ResumeThread", "OpenProcess",
            "CreateProcess", "ShellExecute", "WinExec", "LoadLibrary", "GetProcAddress", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow", "RegSetValueEx", "RegCreateKeyEx", "CryptEncrypt", "CryptDecrypt",
            "CryptAcquireContext", "InternetOpen", "InternetOpenUrl", "InternetReadFile", "URLDownloadToFile", "HttpSendRequest", "WSAStartup",
            "connect", "CreateService", "StartService", "AdjustTokenPrivileges", "OpenProcessToken", "CreateToolhelp32Snapshot", "Process32Next",
            "FindFirstFile", "DeleteFile", "MoveFileEx", "CreateFile", "WriteFile", "GetTickCount", "Sleep", "TerminateProcess", "CreateMutex",
            "FindResource", "LoadResource", "_CorExeMain" };
        // data-directory indices of: EXPORT IMPORT RESOURCE EXCEPTION SECURITY BASERELOC DEBUG TLS LOAD_CONFIG BOUND_IMPORT IAT DELAY_IMPORT COM_DESCRIPTOR
        static readonly (string name, int idx)[] DataDirs =
        {
            ("EXPORT", 0), ("IMPORT", 1), ("RESOURCE", 2), ("EXCEPTION", 3), ("SECURITY", 4), ("BASERELOC", 5), ("DEBUG", 6), ("TLS", 9),
            ("LOAD_CONFIG", 10), ("BOUND_IMPORT", 11), ("IAT", 12), ("DELAY_IMPORT", 13), ("COM_DESCRIPTOR", 14),
        };

        public static readonly string[] Names = BuildNames();

        static string[] BuildNames()
        {
            var n = new List<string> { "size_log", "file_entropy" };
            for (int i = 0; i < 16; i++) n.Add("hist16_" + i);
            n.AddRange(new[] { "frac_zero", "frac_ff", "frac_printable", "str_num_log", "str_avlen", "str_printable_frac", "str_entropy",
                "coff_timestamp", "machine_amd64", "machine_i386", "n_sections", "n_symbols_log", "sizeof_opt_header", "has_symtab" });
            n.AddRange(CoffFlags.Select(f => "coff_" + f.name));
            n.AddRange(new[] { "magic_pe32plus", "subsys_gui", "subsys_cui", "subsys_native" });
            n.AddRange(OptNum.Select(f => "opt_" + f));
            n.AddRange(OptLog.Select(f => "opt_" + f + "_log"));
            n.AddRange(new[] { "checksum_zero", "n_rvas", "e_lfanew" });
            n.AddRange(DllFlags.Select(f => "dllchar_" + f.name));
            n.AddRange(new[] { "sec_zero_size", "sec_high_entropy", "sec_mean_entropy", "sec_max_entropy", "sec_min_entropy", "sec_exec", "sec_write",
                "sec_wx", "sec_empty_name", "sec_nonstd_name", "sec_raw_frac", "sec_max_vratio_log", "entry_is_text", "entry_std_name", "entry_entropy",
                "entry_writable", "entry_missing", "overlay_size_log", "overlay_ratio", "overlay_entropy", "imp_n_dll", "imp_n_func_log" });
            n.AddRange(ImportDlls.Select(d => "dll_" + d));
            n.AddRange(ImportApis.Select(a => "api_" + a));
            n.Add("exp_n_log");
            n.AddRange(DataDirs.Select(d => "dd_" + d.name + "_log"));
            n.Add("rich_n_log");
            return n.ToArray();
        }

        static double Lg(double x) => x > 0 ? Math.Log(1.0 + x) : 0.0;

        /// <summary>Printable-string statistics exactly as the training extractor: runs of 0x20..0x7f of length ≥ 5.</summary>
        public static (int count, double avgLen, long printables, double entropy) StringStats(byte[] d)
        {
            var hist = new long[96];
            int count = 0; long total = 0; int run = 0;
            for (int i = 0; i <= d.Length; i++)
            {
                bool pr = i < d.Length && d[i] >= 0x20 && d[i] <= 0x7f;
                if (pr) { run++; continue; }
                if (run >= 5)
                {
                    count++; total += run;
                    for (int k = i - run; k < i; k++) hist[d[k] - 0x20]++;
                }
                run = 0;
            }
            double h = 0;
            if (total > 0) foreach (long c in hist) if (c > 0) { double p = c / (double)total; h -= p * Math.Log2(p); }
            return (count, count == 0 ? 0 : total / (double)count, total, h);
        }

        public static double[] Extract(PeFile pe)
        {
            var f = new List<double>(Names.Length);
            byte[] d = pe.Data;
            double size = Math.Max(d.Length, 1);
            var hist = new long[256];
            foreach (byte b in d) hist[b]++;
            double ent = 0;
            foreach (long c in hist) if (c > 0) { double p = c / (double)d.Length; ent -= p * Math.Log2(p); }
            f.Add(Lg(size)); f.Add(ent);
            for (int i = 0; i < 16; i++) { long s = 0; for (int k = 0; k < 16; k++) s += hist[i * 16 + k]; f.Add(s / size); }
            f.Add(hist[0] / size); f.Add(hist[255] / size);
            { long s = 0; for (int k = 32; k < 127; k++) s += hist[k]; f.Add(s / size); }

            var st = StringStats(d);
            f.Add(Lg(st.count)); f.Add(st.avgLen); f.Add(st.printables / size); f.Add(st.entropy);

            f.Add(pe.TimeDateStamp);
            f.Add(pe.Machine == 0x8664 ? 1 : 0); f.Add(pe.Machine == 0x14c ? 1 : 0);
            f.Add(pe.NumberOfSections); f.Add(Lg(pe.NumberOfSymbols)); f.Add(pe.SizeOfOptionalHeader); f.Add(pe.PointerToSymbolTable > 0 ? 1 : 0);
            foreach (var fl in CoffFlags) f.Add((pe.Characteristics & fl.bit) != 0 ? 1 : 0);

            f.Add(pe.Magic == 523 ? 1 : 0);
            f.Add(pe.Subsystem == 2 ? 1 : 0); f.Add(pe.Subsystem == 3 ? 1 : 0); f.Add(pe.Subsystem == 1 ? 1 : 0);
            f.Add(pe.MajorImage); f.Add(pe.MinorImage); f.Add(pe.MajorLinker); f.Add(pe.MinorLinker);
            f.Add(pe.MajorOs); f.Add(pe.MinorOs); f.Add(pe.MajorSubsys); f.Add(pe.MinorSubsys);
            f.Add(Lg(pe.SizeOfCode)); f.Add(Lg(pe.SizeOfHeaders)); f.Add(Lg(pe.SizeOfImage)); f.Add(Lg(pe.SizeOfInitializedData));
            f.Add(Lg(pe.SizeOfUninitializedData)); f.Add(Lg(pe.StackReserve)); f.Add(Lg(pe.StackCommit)); f.Add(Lg(pe.HeapReserve));
            f.Add(Lg(pe.HeapCommit)); f.Add(Lg(pe.AddressOfEntryPoint)); f.Add(Lg(pe.BaseOfCode)); f.Add(Lg(pe.ImageBase)); f.Add(Lg(pe.SectionAlignment));
            f.Add(pe.CheckSum == 0 ? 1 : 0); f.Add(pe.NumberOfRvaAndSizes); f.Add(pe.ELfanew);
            foreach (var fl in DllFlags) f.Add((pe.DllCharacteristics & fl.bit) != 0 ? 1 : 0);

            int nZero = 0, nHigh = 0, nExec = 0, nWrite = 0, nWx = 0, nEmpty = 0, nNonStd = 0;
            double rawSum = 0, maxVr = 0;
            foreach (var s in pe.Sections)
            {
                rawSum += s.SizeOfRawData;
                if (s.SizeOfRawData == 0) nZero++;
                if (s.Entropy > 7.0) nHigh++;
                if (s.Exec) nExec++;
                if (s.Write) nWrite++;
                if (s.Exec && s.Write) nWx++;
                if (s.Name == "") nEmpty++; else if (!StdSections.Contains(s.Name)) nNonStd++;
                maxVr = Math.Max(maxVr, s.VirtualSize / Math.Max((double)s.SizeOfRawData, 1.0));
            }
            var ents = pe.Sections.Select(s => s.Entropy).ToList();
            f.Add(nZero); f.Add(nHigh);
            f.Add(ents.Count > 0 ? ents.Sum() / ents.Count : 0); f.Add(ents.Count > 0 ? ents.Max() : 0); f.Add(ents.Count > 0 ? ents.Min() : 0);
            f.Add(nExec); f.Add(nWrite); f.Add(nWx); f.Add(nEmpty); f.Add(nNonStd);
            f.Add(Math.Min(rawSum / size, 4.0)); f.Add(Lg(maxVr));

            // entry section: the LAST section containing the entry point, else the first executable one
            string entry = "";
            foreach (var s in pe.Sections) if (pe.Contains(s, pe.AddressOfEntryPoint)) entry = s.Name;
            for (int i = 0; entry == "" && i < pe.Sections.Count; i++) if (pe.Sections[i].Exec) entry = pe.Sections[i].Name;
            var es = pe.Sections.FirstOrDefault(s => s.Name == entry);
            f.Add(entry == ".text" ? 1 : 0); f.Add(StdSections.Contains(entry) ? 1 : 0);
            f.Add(es != null ? es.Entropy : 0); f.Add(es != null && es.Write ? 1 : 0); f.Add(es == null ? 1 : 0);

            if (pe.OverlayOffset >= 0)
            {
                int ol = d.Length - (int)pe.OverlayOffset;
                f.Add(Lg(ol)); f.Add(ol / (double)d.Length);
                f.Add(Core.Util.Entropy(new ReadOnlySpan<byte>(d, (int)pe.OverlayOffset, ol)));
            }
            else { f.Add(0); f.Add(0); f.Add(0); }

            var funcs = new HashSet<string>(StringComparer.Ordinal);
            int nFunc = 0;
            var dlls = new List<string>();
            foreach (var kv in pe.Imports) { dlls.Add(kv.Key.ToLowerInvariant()); nFunc += kv.Value.Count; foreach (string fn in kv.Value) funcs.Add(fn); }
            f.Add(dlls.Count); f.Add(Lg(nFunc));
            foreach (string dn in ImportDlls) f.Add(dlls.Any(x => x.StartsWith(dn, StringComparison.Ordinal)) ? 1 : 0);
            foreach (string an in ImportApis) f.Add(funcs.Contains(an) || funcs.Contains(an + "A") || funcs.Contains(an + "W") ? 1 : 0);

            f.Add(Lg(pe.ExportCount));
            foreach (var dd in DataDirs) f.Add(dd.idx < pe.DirCount ? Lg(pe.Dirs[dd.idx].size) : 0);
            f.Add(Lg(pe.RichPairs));

            if (f.Count != Names.Length) throw new InvalidOperationException($"feature count {f.Count} != {Names.Length}");
            return f.ToArray();
        }
    }
}
