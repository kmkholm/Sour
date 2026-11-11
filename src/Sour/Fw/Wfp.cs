using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Sour.Fw
{
    /// <summary>One Windows Filtering Platform filter, described independently of the native structs.</summary>
    public sealed class FilterSpec
    {
        public string Name;
        public bool Outbound = true;     // true: ALE_AUTH_CONNECT, false: ALE_AUTH_RECV_ACCEPT
        public bool V6;
        public bool Block;
        public byte Weight;              // 0..15, higher wins inside the Sour sublayer
        public string AppPath;           // null = any application
        public bool Loopback;
        public byte? Protocol;           // 6 TCP, 17 UDP, 58 ICMPv6 ...
        public ushort? RemotePort;
        public ushort? LocalPort;
        public uint? V4Addr, V4Mask;     // host byte order
        public byte[] V6Addr; public byte V6Prefix;

        public override string ToString() =>
            $"{(Block ? "BLOCK" : "PERMIT")} {(Outbound ? "out" : "in")} {(V6 ? "v6" : "v4")} w{Weight} app={AppPath ?? "*"}" +
            $"{(Loopback ? " loopback" : "")}{(Protocol.HasValue ? " proto=" + Protocol : "")}{(RemotePort.HasValue ? " rport=" + RemotePort : "")}" +
            $"{(LocalPort.HasValue ? " lport=" + LocalPort : "")}{(V4Addr.HasValue ? $" ip={V4Addr:X8}/{V4Mask:X8}" : "")}{(V6Addr != null ? " ip6/" + V6Prefix : "")}";
    }

    public sealed class WfpFilterInfo
    {
        public ulong Id; public Guid Key; public string Name; public Guid Layer; public bool Block; public bool Persistent;
    }

    public sealed class WfpException : Exception
    {
        public uint Code;
        public WfpException(string op, uint code) : base($"{op} failed: 0x{code:X8} ({Wfp.Describe(code)})") { Code = code; }
    }

    /// <summary>
    /// User-mode Windows Filtering Platform client (fwpuclnt.dll). No kernel driver: Sour adds its own provider and
    /// sublayer and places PERMIT/BLOCK filters at the ALE connect / receive-accept layers, which is the same
    /// mechanism Windows Firewall itself uses. Structures follow fwpmtypes.h / fwptypes.h (Windows SDK 10.0.26100).
    /// </summary>
    public sealed unsafe class Wfp : IDisposable
    {
        // ---- identity of everything Sour owns inside the Base Filtering Engine
        public static readonly Guid ProviderKey = new Guid("5a7d5e10-50a4-4b6f-9d53-2f6c1b7e0a01");
        public static readonly Guid SubLayerKey = new Guid("5a7d5e10-50a4-4b6f-9d53-2f6c1b7e0a02");

        // ---- layers and condition fields (fwpmu.h)
        public static readonly Guid LayerConnectV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        public static readonly Guid LayerConnectV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        public static readonly Guid LayerAcceptV4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
        public static readonly Guid LayerAcceptV6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
        public static readonly Guid[] Layers = { LayerConnectV4, LayerConnectV6, LayerAcceptV4, LayerAcceptV6 };

        static readonly Guid CondAppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        static readonly Guid CondRemoteAddr = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        static readonly Guid CondRemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
        static readonly Guid CondLocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
        static readonly Guid CondProtocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        static readonly Guid CondFlags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");

        const uint FWP_ACTION_BLOCK = 0x1001, FWP_ACTION_PERMIT = 0x1002;
        const uint FWP_UINT8 = 1, FWP_UINT16 = 2, FWP_UINT32 = 3, FWP_BYTE_BLOB_TYPE = 12, FWP_V4_ADDR_MASK = 0x100, FWP_V6_ADDR_MASK = 0x101;
        const uint FWP_MATCH_EQUAL = 0, FWP_MATCH_FLAGS_ALL_SET = 6;
        const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 1;
        const uint FWPM_SESSION_FLAG_DYNAMIC = 1;
        const uint FWPM_PROVIDER_FLAG_PERSISTENT = 1, FWPM_SUBLAYER_FLAG_PERSISTENT = 1, FWPM_FILTER_FLAG_PERSISTENT = 1;
        const uint RPC_C_AUTHN_WINNT = 10;
        public const uint FWP_E_ALREADY_EXISTS = 0x80320009, FWP_E_FILTER_NOT_FOUND = 0x80320003,
                          FWP_E_PROVIDER_NOT_FOUND = 0x80320005, FWP_E_SUBLAYER_NOT_FOUND = 0x80320007, FWP_E_IN_USE = 0x8032000A;

        [StructLayout(LayoutKind.Sequential)] public struct FWPM_DISPLAY_DATA0 { public IntPtr name, description; }
        [StructLayout(LayoutKind.Sequential)] public struct FWP_BYTE_BLOB { public uint size; public IntPtr data; }
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_SESSION0
        {
            public Guid sessionKey; public FWPM_DISPLAY_DATA0 displayData; public uint flags, txnWaitTimeoutInMSec, processId;
            public IntPtr sid, username; public int kernelMode;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_PROVIDER0
        {
            public Guid providerKey; public FWPM_DISPLAY_DATA0 displayData; public uint flags; public FWP_BYTE_BLOB providerData; public IntPtr serviceName;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_SUBLAYER0
        {
            public Guid subLayerKey; public FWPM_DISPLAY_DATA0 displayData; public uint flags; public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData; public ushort weight;
        }
        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public struct FWP_VALUE0
        {
            [FieldOffset(0)] public uint type;
            [FieldOffset(8)] public byte uint8;
            [FieldOffset(8)] public ushort uint16;
            [FieldOffset(8)] public uint uint32;
            [FieldOffset(8)] public IntPtr ptr;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_FILTER_CONDITION0 { public Guid fieldKey; public uint matchType; public FWP_VALUE0 conditionValue; }
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_ACTION0 { public uint type; public Guid filterType; }
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_FILTER0
        {
            public Guid filterKey; public FWPM_DISPLAY_DATA0 displayData; public uint flags; public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData; public Guid layerKey, subLayerKey; public FWP_VALUE0 weight;
            public uint numFilterConditions; public IntPtr filterCondition; public FWPM_ACTION0 action;
            public ulong rawContext, contextPad; public IntPtr reserved; public ulong filterId; public FWP_VALUE0 effectiveWeight;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct FWPM_FILTER_ENUM_TEMPLATE0
        {
            public IntPtr providerKey; public Guid layerKey; public int enumType; public uint flags; public IntPtr providerContextTemplate;
            public uint numFilterConditions; public IntPtr filterCondition; public uint actionMask; public IntPtr calloutKey;
        }
        [StructLayout(LayoutKind.Sequential)] struct FWP_V4_ADDR_AND_MASK { public uint addr, mask; }

        const string Dll = "fwpuclnt.dll";
        [DllImport(Dll, CharSet = CharSet.Unicode)] static extern uint FwpmEngineOpen0(string serverName, uint authnService, IntPtr authIdentity, ref FWPM_SESSION0 session, out IntPtr engine);
        [DllImport(Dll)] static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport(Dll)] static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport(Dll)] static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport(Dll)] static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport(Dll)] static extern uint FwpmProviderAdd0(IntPtr engine, ref FWPM_PROVIDER0 provider, IntPtr sd);
        [DllImport(Dll)] static extern uint FwpmProviderDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport(Dll)] static extern uint FwpmSubLayerAdd0(IntPtr engine, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);
        [DllImport(Dll)] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport(Dll)] static extern uint FwpmFilterAdd0(IntPtr engine, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);
        [DllImport(Dll)] static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);
        [DllImport(Dll, CharSet = CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
        [DllImport(Dll)] static extern void FwpmFreeMemory0(ref IntPtr p);
        [DllImport(Dll)] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr enumTemplate, out IntPtr enumHandle);
        [DllImport(Dll)] static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumHandle, uint requested, out IntPtr entries, out uint returned);
        [DllImport(Dll)] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumHandle);

        IntPtr _engine;
        public bool Dynamic { get; }

        public static string Describe(uint code) => code switch
        {
            0 => "ok",
            5 => "access denied - administrator rights are required",
            0x80320009 => "already exists",
            0x80320003 => "filter not found",
            0x80320005 => "provider not found",
            0x80320007 => "sublayer not found",
            0x8032000A => "in use",
            0x80320002 => "callout not found",
            0x80320012 => "session aborted",
            0x8032001E => "invalid enumerator",
            0x80320023 => "null pointer",
            0x80320024 => "invalid enumerator",
            0x80320025 => "invalid flags",
            0x80320035 => "invalid parameter",
            0x00000057 => "invalid parameter",
            1753 => "base filtering engine service is not running",
            _ => "see WFP error codes",
        };

        /// <summary>Layout guard: the native API reads these structs raw, so their size must match the SDK (x64).</summary>
        public static List<(string name, int actual, int expected)> StructSizes() => new List<(string, int, int)>
        {
            ("FWPM_SESSION0", sizeof(FWPM_SESSION0), 72),
            ("FWPM_PROVIDER0", sizeof(FWPM_PROVIDER0), 64),
            ("FWPM_SUBLAYER0", sizeof(FWPM_SUBLAYER0), 72),
            ("FWP_VALUE0", sizeof(FWP_VALUE0), 16),
            ("FWPM_FILTER_CONDITION0", sizeof(FWPM_FILTER_CONDITION0), 40),
            ("FWPM_ACTION0", sizeof(FWPM_ACTION0), 20),
            ("FWPM_FILTER0", sizeof(FWPM_FILTER0), 200),
            ("FWPM_FILTER_ENUM_TEMPLATE0", sizeof(FWPM_FILTER_ENUM_TEMPLATE0), 72),
            ("FWP_BYTE_BLOB", sizeof(FWP_BYTE_BLOB), 16),
        };

        public Wfp(bool dynamicSession = false)
        {
            Dynamic = dynamicSession;
            var s = new FWPM_SESSION0 { flags = dynamicSession ? FWPM_SESSION_FLAG_DYNAMIC : 0, txnWaitTimeoutInMSec = 5000 };
            uint r = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, ref s, out _engine);
            if (r != 0) throw new WfpException("FwpmEngineOpen0", r);
        }

        public void Dispose()
        {
            if (_engine != IntPtr.Zero) { FwpmEngineClose0(_engine); _engine = IntPtr.Zero; }
        }

        static void Check(string op, uint r, params uint[] tolerated)
        {
            if (r == 0) return;
            foreach (uint t in tolerated) if (r == t) return;
            throw new WfpException(op, r);
        }

        public void Begin() => Check("FwpmTransactionBegin0", FwpmTransactionBegin0(_engine, 0));
        public void Commit() => Check("FwpmTransactionCommit0", FwpmTransactionCommit0(_engine));
        public void Abort() { FwpmTransactionAbort0(_engine); }

        /// <summary>Kernel-format application id ("\device\harddiskvolume3\...") for a file, as WFP matches it.</summary>
        public static string AppIdString(string path)
        {
            uint r = FwpmGetAppIdFromFileName0(path, out IntPtr blob);
            if (r != 0) return null;
            try
            {
                var b = Marshal.PtrToStructure<FWP_BYTE_BLOB>(blob);
                return Marshal.PtrToStringUni(b.data, (int)b.size / 2).TrimEnd('\0');
            }
            finally { FwpmFreeMemory0(ref blob); }
        }

        public void EnsureProviderAndSubLayer(bool persistent)
        {
            IntPtr name = Marshal.StringToHGlobalUni("Sour Firewall");
            IntPtr desc = Marshal.StringToHGlobalUni("Sour AI firewall provider");
            try
            {
                var p = new FWPM_PROVIDER0
                {
                    providerKey = ProviderKey,
                    displayData = new FWPM_DISPLAY_DATA0 { name = name, description = desc },
                    flags = persistent ? FWPM_PROVIDER_FLAG_PERSISTENT : 0,
                };
                Check("FwpmProviderAdd0", FwpmProviderAdd0(_engine, ref p, IntPtr.Zero), FWP_E_ALREADY_EXISTS);

                Guid prov = ProviderKey;
                var sl = new FWPM_SUBLAYER0
                {
                    subLayerKey = SubLayerKey,
                    displayData = new FWPM_DISPLAY_DATA0 { name = name, description = desc },
                    flags = persistent ? FWPM_SUBLAYER_FLAG_PERSISTENT : 0,
                    providerKey = (IntPtr)(&prov),
                    weight = 0xFFF0,       // evaluated before ordinary sublayers; a BLOCK in any sublayer is final
                };
                Check("FwpmSubLayerAdd0", FwpmSubLayerAdd0(_engine, ref sl, IntPtr.Zero), FWP_E_ALREADY_EXISTS);
            }
            finally { Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(desc); }
        }

        /// <summary>Adds one filter. Returns its runtime id, or 0 when the application file no longer exists.</summary>
        public ulong AddFilter(FilterSpec f, bool persistent)
        {
            var allocs = new List<IntPtr>();
            IntPtr appBlob = IntPtr.Zero;
            try
            {
                var conds = new List<FWPM_FILTER_CONDITION0>();
                if (!string.IsNullOrEmpty(f.AppPath))
                {
                    uint ar = FwpmGetAppIdFromFileName0(f.AppPath, out appBlob);
                    if (ar != 0) return 0;
                    conds.Add(new FWPM_FILTER_CONDITION0 { fieldKey = CondAppId, matchType = FWP_MATCH_EQUAL, conditionValue = new FWP_VALUE0 { type = FWP_BYTE_BLOB_TYPE, ptr = appBlob } });
                }
                if (f.Loopback)
                    conds.Add(new FWPM_FILTER_CONDITION0 { fieldKey = CondFlags, matchType = FWP_MATCH_FLAGS_ALL_SET, conditionValue = new FWP_VALUE0 { type = FWP_UINT32, uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK } });
                if (f.Protocol.HasValue)
                    conds.Add(new FWPM_FILTER_CONDITION0 { fieldKey = CondProtocol, matchType = FWP_MATCH_EQUAL, conditionValue = new FWP_VALUE0 { type = FWP_UINT8, uint8 = f.Protocol.Value } });
                if (f.RemotePort.HasValue)
                    conds.Add(new FWPM_FILTER_CONDITION0 { fieldKey = CondRemotePort, matchType = FWP_MATCH_EQUAL, conditionValue = new FWP_VALUE0 { type = FWP_UINT16, uint16 = f.RemotePort.Value } });
                if (f.LocalPort.HasValue)
                    conds.Add(new FWPM_FILTER_CONDITION0 { fieldKey = CondLocalPort, matchType = FWP_MATCH_EQUAL, conditionValue = new FWP_VALUE0 { type = FWP_UINT16, uint16 = f.LocalPort.Value } });
                if (!f.V6 && f.V4Addr.HasValue)
                {
                    IntPtr m = Marshal.AllocHGlobal(sizeof(FWP_V4_ADDR_AND_MASK)); allocs.Add(m);
                    *(FWP_V4_ADDR_AND_MASK*)m = new FWP_V4_ADDR_AND_MASK { addr = f.V4Addr.Value, mask = f.V4Mask ?? 0xFFFFFFFF };
                    conds.Add(new FWPM_FILTER_CONDITION0 { fieldKey = CondRemoteAddr, matchType = FWP_MATCH_EQUAL, conditionValue = new FWP_VALUE0 { type = FWP_V4_ADDR_MASK, ptr = m } });
                }
                if (f.V6 && f.V6Addr != null && f.V6Addr.Length == 16)
                {
                    IntPtr m = Marshal.AllocHGlobal(17); allocs.Add(m);   // FWP_V6_ADDR_AND_MASK { UINT8 addr[16]; UINT8 prefixLength; }
                    Marshal.Copy(f.V6Addr, 0, m, 16);
                    Marshal.WriteByte(m, 16, f.V6Prefix);
                    conds.Add(new FWPM_FILTER_CONDITION0 { fieldKey = CondRemoteAddr, matchType = FWP_MATCH_EQUAL, conditionValue = new FWP_VALUE0 { type = FWP_V6_ADDR_MASK, ptr = m } });
                }

                IntPtr condPtr = IntPtr.Zero;
                if (conds.Count > 0)
                {
                    condPtr = Marshal.AllocHGlobal(sizeof(FWPM_FILTER_CONDITION0) * conds.Count); allocs.Add(condPtr);
                    for (int i = 0; i < conds.Count; i++) ((FWPM_FILTER_CONDITION0*)condPtr)[i] = conds[i];
                }
                IntPtr name = Marshal.StringToHGlobalUni("Sour: " + (f.Name ?? "rule")); allocs.Add(name);
                Guid prov = ProviderKey;
                var flt = new FWPM_FILTER0
                {
                    filterKey = Guid.NewGuid(),
                    displayData = new FWPM_DISPLAY_DATA0 { name = name, description = name },
                    flags = persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0,
                    providerKey = (IntPtr)(&prov),
                    layerKey = f.Outbound ? (f.V6 ? LayerConnectV6 : LayerConnectV4) : (f.V6 ? LayerAcceptV6 : LayerAcceptV4),
                    subLayerKey = SubLayerKey,
                    weight = new FWP_VALUE0 { type = FWP_UINT8, uint8 = f.Weight },
                    numFilterConditions = (uint)conds.Count,
                    filterCondition = condPtr,
                    action = new FWPM_ACTION0 { type = f.Block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT },
                };
                Check("FwpmFilterAdd0", FwpmFilterAdd0(_engine, ref flt, IntPtr.Zero, out ulong id));
                return id;
            }
            finally
            {
                foreach (var a in allocs) Marshal.FreeHGlobal(a);
                if (appBlob != IntPtr.Zero) FwpmFreeMemory0(ref appBlob);
            }
        }

        /// <summary>Lists the filters that belong to the Sour provider (all four layers).</summary>
        public List<WfpFilterInfo> EnumOwnFilters()
        {
            var res = new List<WfpFilterInfo>();
            Guid prov = ProviderKey;
            foreach (Guid layer in Layers)
            {
                var tpl = new FWPM_FILTER_ENUM_TEMPLATE0 { providerKey = (IntPtr)(&prov), layerKey = layer, enumType = 1, flags = 0, actionMask = 0xFFFFFFFF };
                Check("FwpmFilterCreateEnumHandle0", FwpmFilterCreateEnumHandle0(_engine, (IntPtr)(&tpl), out IntPtr h));
                try
                {
                    while (true)
                    {
                        Check("FwpmFilterEnum0", FwpmFilterEnum0(_engine, h, 256, out IntPtr entries, out uint n));
                        if (n == 0) { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); break; }
                        try
                        {
                            for (uint i = 0; i < n; i++)
                            {
                                var fp = (FWPM_FILTER0*)Marshal.ReadIntPtr(entries, (int)i * IntPtr.Size);
                                if (fp->providerKey == IntPtr.Zero || *(Guid*)fp->providerKey != ProviderKey) continue;
                                res.Add(new WfpFilterInfo
                                {
                                    Id = fp->filterId, Key = fp->filterKey, Layer = fp->layerKey,
                                    Name = fp->displayData.name == IntPtr.Zero ? "" : Marshal.PtrToStringUni(fp->displayData.name),
                                    Block = fp->action.type == FWP_ACTION_BLOCK, Persistent = (fp->flags & FWPM_FILTER_FLAG_PERSISTENT) != 0,
                                });
                            }
                        }
                        finally { FwpmFreeMemory0(ref entries); }
                        if (n < 256) break;
                    }
                }
                finally { FwpmFilterDestroyEnumHandle0(_engine, h); }
            }
            return res;
        }

        public int DeleteOwnFilters()
        {
            int n = 0;
            foreach (var f in EnumOwnFilters())
            {
                Check("FwpmFilterDeleteById0", FwpmFilterDeleteById0(_engine, f.Id), FWP_E_FILTER_NOT_FOUND);
                n++;
            }
            return n;
        }

        /// <summary>Removes filters, sublayer and provider: Sour leaves nothing behind in the filtering engine.</summary>
        public int RemoveEverything()
        {
            int n = DeleteOwnFilters();
            Guid sl = SubLayerKey, pv = ProviderKey;
            Check("FwpmSubLayerDeleteByKey0", FwpmSubLayerDeleteByKey0(_engine, ref sl), FWP_E_SUBLAYER_NOT_FOUND, FWP_E_IN_USE);
            Check("FwpmProviderDeleteByKey0", FwpmProviderDeleteByKey0(_engine, ref pv), FWP_E_PROVIDER_NOT_FOUND, FWP_E_IN_USE);
            return n;
        }
    }
}
