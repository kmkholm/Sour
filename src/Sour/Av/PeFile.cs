using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sour.Av
{
    public sealed class PeSection
    {
        public string Name;          // stripped of NULs, lower-cased (as the training extractor does)
        public uint VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics;
        public double Entropy;
        public uint? NextVirtualAddress;
        public bool Exec => (Characteristics & 0x20000000) != 0;
        public bool Write => (Characteristics & 0x80000000) != 0;
        public bool Code => (Characteristics & 0x20) != 0;
    }

    /// <summary>
    /// Read-only PE parser. Address translation, section data ranges, overlay and Rich-header rules deliberately
    /// follow pefile 2024.8.26, because the ML model was trained on features produced by that library.
    /// </summary>
    public sealed class PeFile
    {
        public byte[] Data;
        public bool Valid;
        public string Error;
        public uint ELfanew;
        public ushort Machine, NumberOfSections, SizeOfOptionalHeader, Characteristics;
        public uint TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
        public ushort Magic, Subsystem, DllCharacteristics;
        public byte MajorLinker, MinorLinker;
        public ushort MajorOs, MinorOs, MajorImage, MinorImage, MajorSubsys, MinorSubsys;
        public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode;
        public uint SectionAlignment, FileAlignment, SizeOfImage, SizeOfHeaders, CheckSum, NumberOfRvaAndSizes;
        public ulong ImageBase, StackReserve, StackCommit, HeapReserve, HeapCommit;
        public int OptionalHeaderOffset;
        public (uint rva, uint size)[] Dirs = new (uint, uint)[16];
        public int DirCount;
        public List<PeSection> Sections = new List<PeSection>();
        public List<KeyValuePair<string, List<string>>> Imports = new List<KeyValuePair<string, List<string>>>();
        public int ExportCount;
        public List<string> ExportNames = new List<string>();
        public int RichPairs;
        public long OverlayOffset = -1;
        public bool Is64 => Magic == 0x20b;
        public bool IsDll => (Characteristics & 0x2000) != 0;
        public bool IsDotNet => DirCount > 14 && Dirs[14].size > 0;

        ushort U16(long o) => o >= 0 && o + 2 <= Data.Length ? BitConverter.ToUInt16(Data, (int)o) : (ushort)0;
        uint U32(long o) => o >= 0 && o + 4 <= Data.Length ? BitConverter.ToUInt32(Data, (int)o) : 0u;
        ulong U64(long o) => o >= 0 && o + 8 <= Data.Length ? BitConverter.ToUInt64(Data, (int)o) : 0ul;

        public static bool LooksLikePe(byte[] head) => head != null && head.Length >= 2 && head[0] == 'M' && head[1] == 'Z';

        public static PeFile Parse(byte[] data)
        {
            var pe = new PeFile { Data = data };
            try { pe.ParseCore(); }
            catch (Exception ex) { pe.Valid = false; pe.Error = ex.Message; }
            return pe;
        }

        void ParseCore()
        {
            if (Data.Length < 0x40 || Data[0] != 'M' || Data[1] != 'Z') { Error = "no MZ header"; return; }
            ELfanew = U32(0x3C);
            long nt = ELfanew;
            if (nt + 24 > Data.Length || U32(nt) != 0x00004550) { Error = "no PE signature"; return; }
            long coff = nt + 4;
            Machine = U16(coff); NumberOfSections = U16(coff + 2); TimeDateStamp = U32(coff + 4);
            PointerToSymbolTable = U32(coff + 8); NumberOfSymbols = U32(coff + 12);
            SizeOfOptionalHeader = U16(coff + 16); Characteristics = U16(coff + 18);
            long o = coff + 20; OptionalHeaderOffset = (int)o;
            Magic = U16(o);
            if (Magic != 0x10b && Magic != 0x20b) { Error = "unknown optional header magic"; return; }
            MajorLinker = Data[o + 2]; MinorLinker = Data[o + 3];
            SizeOfCode = U32(o + 4); SizeOfInitializedData = U32(o + 8); SizeOfUninitializedData = U32(o + 12);
            AddressOfEntryPoint = U32(o + 16); BaseOfCode = U32(o + 20);
            long dirs;
            if (Magic == 0x10b)
            {
                ImageBase = U32(o + 28); SectionAlignment = U32(o + 32); FileAlignment = U32(o + 36);
                MajorOs = U16(o + 40); MinorOs = U16(o + 42); MajorImage = U16(o + 44); MinorImage = U16(o + 46);
                MajorSubsys = U16(o + 48); MinorSubsys = U16(o + 50);
                SizeOfImage = U32(o + 56); SizeOfHeaders = U32(o + 60); CheckSum = U32(o + 64);
                Subsystem = U16(o + 68); DllCharacteristics = U16(o + 70);
                StackReserve = U32(o + 72); StackCommit = U32(o + 76); HeapReserve = U32(o + 80); HeapCommit = U32(o + 84);
                NumberOfRvaAndSizes = U32(o + 92); dirs = o + 96;
            }
            else
            {
                ImageBase = U64(o + 24); SectionAlignment = U32(o + 32); FileAlignment = U32(o + 36);
                MajorOs = U16(o + 40); MinorOs = U16(o + 42); MajorImage = U16(o + 44); MinorImage = U16(o + 46);
                MajorSubsys = U16(o + 48); MinorSubsys = U16(o + 50);
                SizeOfImage = U32(o + 56); SizeOfHeaders = U32(o + 60); CheckSum = U32(o + 64);
                Subsystem = U16(o + 68); DllCharacteristics = U16(o + 70);
                StackReserve = U64(o + 72); StackCommit = U64(o + 80); HeapReserve = U64(o + 88); HeapCommit = U64(o + 96);
                NumberOfRvaAndSizes = U32(o + 108); dirs = o + 112;
            }
            DirCount = (int)Math.Min(NumberOfRvaAndSizes & 0x7FFFFFFF, 16);
            for (int i = 0; i < DirCount; i++)
            {
                if (dirs + i * 8 >= Data.Length) { DirCount = i; break; }
                Dirs[i] = (U32(dirs + i * 8), U32(dirs + i * 8 + 4));
            }

            long so = o + SizeOfOptionalHeader;
            int ns = Math.Min((int)NumberOfSections, 0x800);
            for (int i = 0; i < ns; i++)
            {
                long s = so + i * 40L;
                if (s + 40 > Data.Length) break;
                int a = 0, b = 8;
                while (a < 8 && Data[s + a] == 0) a++;
                while (b > a && Data[s + b - 1] == 0) b--;
                var sb = new StringBuilder();
                // python: bytes.decode(errors="ignore") = UTF-8 with invalid sequences dropped
                string nm = new UTF8Encoding(false, false).GetString(Data, (int)s + a, b - a).Replace("�", "");
                var sec = new PeSection
                {
                    Name = nm.ToLowerInvariant(),
                    VirtualSize = U32(s + 8), VirtualAddress = U32(s + 12), SizeOfRawData = U32(s + 16),
                    PointerToRawData = U32(s + 20), Characteristics = U32(s + 36),
                };
                Sections.Add(sec);
            }
            // pefile: next_section_virtual_address is taken over sections ordered by VirtualAddress
            var ordered = Sections.OrderBy(x => x.VirtualAddress).ToList();
            for (int i = 0; i + 1 < ordered.Count; i++) ordered[i].NextVirtualAddress = ordered[i + 1].VirtualAddress;

            foreach (var sec in Sections)
            {
                long start = PtrAdj(sec), end = (long)sec.PointerToRawData + sec.SizeOfRawData;
                if (start > Data.Length) start = Data.Length;
                if (end > Data.Length) end = Data.Length;
                sec.Entropy = end > start ? Core.Util.Entropy(new ReadOnlySpan<byte>(Data, (int)start, (int)(end - start))) : 0.0;
            }
            Valid = true;

            try { ParseImports(); } catch { }
            try { ParseExports(); } catch { }
            try { ParseRich(); } catch { }
            try { ComputeOverlay(); } catch { }
        }

        // ---- pefile address rules
        long PtrAdj(PeSection s)
        {
            long p = FileAlignment >= 0x200 ? (s.PointerToRawData & ~0x1FFu) : s.PointerToRawData;
            if (SectionAlignment < 0x1000 && s.PointerToRawData == s.VirtualAddress) p = s.VirtualAddress;
            return p;
        }
        long VaAdj(PeSection s)
        {
            uint sa = SectionAlignment < 0x1000 ? FileAlignment : SectionAlignment;
            if (sa != 0 && s.VirtualAddress % sa != 0) return (long)sa * (s.VirtualAddress / sa);
            return s.VirtualAddress;
        }
        public bool Contains(PeSection s, uint rva)
        {
            long va = VaAdj(s);
            long size = (Data.Length - PtrAdj(s) < s.SizeOfRawData) ? s.VirtualSize : Math.Max(s.SizeOfRawData, s.VirtualSize);
            if (s.NextVirtualAddress.HasValue && s.NextVirtualAddress.Value > s.VirtualAddress && va + size > s.NextVirtualAddress.Value)
                size = s.NextVirtualAddress.Value - va;
            return va <= rva && rva < va + size;
        }
        public PeSection SectionByRva(uint rva) { foreach (var s in Sections) if (Contains(s, rva)) return s; return null; }

        /// <summary>RVA → file offset, -1 if it cannot be mapped.</summary>
        public long Offset(uint rva)
        {
            var s = SectionByRva(rva);
            if (s == null) return rva < Data.Length ? rva : -1;
            return rva - VaAdj(s) + PtrAdj(s);
        }

        string CStr(long off, int max = 512)
        {
            if (off < 0 || off >= Data.Length) return null;
            int n = 0;
            while (off + n < Data.Length && n < max && Data[off + n] != 0) n++;
            for (int i = 0; i < n; i++) { byte c = Data[off + i]; if (c < 0x20 || c > 0x7e) return null; }
            return Encoding.ASCII.GetString(Data, (int)off, n);
        }

        void ParseImports()
        {
            if (DirCount < 2 || Dirs[1].rva == 0) return;
            long d = Offset(Dirs[1].rva);
            if (d < 0) return;
            int thunk = Is64 ? 8 : 4;
            ulong ordFlag = Is64 ? 0x8000000000000000ul : 0x80000000ul;
            var map = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            for (int i = 0; i < 2048; i++, d += 20)
            {
                if (d + 20 > Data.Length) break;
                uint oft = U32(d), nameRva = U32(d + 12), ft = U32(d + 16);
                if (oft == 0 && nameRva == 0 && ft == 0 && U32(d + 4) == 0 && U32(d + 8) == 0) break;
                string dll = CStr(Offset(nameRva), 256);
                if (string.IsNullOrEmpty(dll)) dll = "*invalid*";
                var funcs = new List<string>();
                long t = Offset(oft != 0 ? oft : ft);
                if (t < 0 && oft != 0) t = Offset(ft);
                for (int k = 0; t >= 0 && k < 0x2000; k++, t += thunk)
                {
                    if (t + thunk > Data.Length) break;
                    ulong v = Is64 ? U64(t) : U32(t);
                    if (v == 0) break;
                    if ((v & ordFlag) != 0)
                    {
                        // pefile resolves Winsock ordinals to names (ordlookup); the two that matter for the feature set:
                        ulong ord = v & 0xFFFF;
                        bool winsock = dll.Equals("ws2_32.dll", StringComparison.OrdinalIgnoreCase) || dll.Equals("wsock32.dll", StringComparison.OrdinalIgnoreCase);
                        funcs.Add(winsock && ord == 4 ? "connect" : winsock && ord == 115 ? "WSAStartup" : dll + ":ordinal" + ord);
                        continue;
                    }
                    string fn = CStr(Offset((uint)(v & 0x7FFFFFFF)) + 2, 512);
                    if (string.IsNullOrEmpty(fn)) break;      // garbage thunk: stop this table
                    funcs.Add(fn);
                }
                if (!map.ContainsKey(dll)) Imports.Add(new KeyValuePair<string, List<string>>(dll, funcs));
                else for (int j = 0; j < Imports.Count; j++) if (Imports[j].Key == dll) Imports[j] = new KeyValuePair<string, List<string>>(dll, funcs);
                map[dll] = funcs;      // a repeated DLL name replaces the earlier list (dict semantics of the extractor)
            }
        }

        void ParseExports()
        {
            if (DirCount < 1 || Dirs[0].rva == 0) return;
            long d = Offset(Dirs[0].rva);
            if (d < 0 || d + 40 > Data.Length) return;
            uint nFuncs = U32(d + 20), nNames = U32(d + 24);
            uint aFuncs = U32(d + 28), aNames = U32(d + 32), aOrds = U32(d + 36);
            nFuncs = Math.Min(nFuncs, 0x40000u); nNames = Math.Min(nNames, 0x40000u);
            long of = Offset(aFuncs), on = Offset(aNames), oo = Offset(aOrds);
            var named = new HashSet<uint>();
            int count = 0;
            if (on >= 0 && oo >= 0)
            {
                for (uint i = 0; i < nNames; i++)
                {
                    string nm = CStr(Offset(U32(on + i * 4)), 512);
                    uint ord = U16(oo + i * 2);
                    if (nm == null) break;
                    named.Add(ord); count++;
                    if (ExportNames.Count < 4000) ExportNames.Add(nm);
                }
            }
            if (of >= 0)
                for (uint i = 0; i < nFuncs; i++)
                    if (!named.Contains(i) && U32(of + i * 4) != 0) count++;
            ExportCount = count;
        }

        void ParseRich()
        {
            const uint DANS = 0x536E6144, RICH = 0x68636952;
            int limit = Math.Min(OptionalHeaderOffset, Data.Length);
            int idx = -1;
            for (int i = 0x80; i + 4 <= limit; i++)
                if (Data[i] == 'R' && Data[i + 1] == 'i' && Data[i + 2] == 'c' && Data[i + 3] == 'h') { idx = i; break; }
            if (idx < 0) return;
            int len = (idx + 8 - 0x80) / 4;
            if (len < 6) return;
            var d = new uint[len];
            for (int i = 0; i < len; i++) d[i] = U32(0x80 + i * 4);
            if (Array.IndexOf(d, RICH) < 0) return;
            uint checksum = d[1];
            if ((d[0] ^ checksum) != DANS || d[2] != checksum || d[3] != checksum) return;
            int pairs = 0;
            for (int i = 0; i < (len - 4) / 2; i++)
            {
                if (d[4 + 2 * i] == RICH) break;
                pairs++;
            }
            RichPairs = pairs;
        }

        void ComputeOverlay()
        {
            long best = 0;
            void Upd(long off, long size) { if (off < 0) return; long sum = off + size; if (best < sum && sum <= Data.Length) best = sum; }
            Upd(OptionalHeaderOffset, SizeOfOptionalHeader);
            foreach (var s in Sections) Upd(s.PointerToRawData, s.SizeOfRawData);
            for (int i = 0; i < DirCount; i++)
            {
                if (i == 4) continue;                    // the certificate table lives outside the image
                Upd(Offset(Dirs[i].rva), Dirs[i].size);
            }
            OverlayOffset = Data.Length > best ? best : -1;
        }
    }
}
