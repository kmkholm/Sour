using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Sour.Av
{
    public sealed class TrustInfo
    {
        public bool Valid;          // Authenticode chain verified by Windows (embedded) or file hash found in a system catalog
        public bool Embedded;       // has an embedded signature block
        public bool Catalog;        // verified through a Windows security catalog
        public string Publisher;    // signer common name
        public string Subject;
        public uint Status;         // WinVerifyTrust result
        public bool IsMicrosoft => Valid && (Catalog || (Subject ?? "").Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase));
        public string Describe() => Valid ? (Catalog ? "Windows catalog" : Publisher) : (Embedded ? "invalid signature" : "unsigned");
    }

    /// <summary>Authenticode verification through WinVerifyTrust plus the Windows catalog database.</summary>
    public static class Trust
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO { public uint cbStruct; public IntPtr pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct; public IntPtr pPolicyCallbackData, pSIPClientData; public uint dwUIChoice, fdwRevocationChecks, dwUnionChoice;
            public IntPtr pFile; public uint dwStateAction; public IntPtr hWVTStateData, pwszURLReference; public uint dwProvFlags, dwUIContext; public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll")] static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint cbHash, byte[] pbHash, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint flags, IntPtr prevCatInfo);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint flags);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);

        static readonly ConcurrentDictionary<string, (long stamp, TrustInfo info)> Cache = new ConcurrentDictionary<string, (long, TrustInfo)>(StringComparer.OrdinalIgnoreCase);

        public static TrustInfo Check(string path)
        {
            long stamp = 0;
            try { var fi = new FileInfo(path); stamp = fi.LastWriteTimeUtc.Ticks ^ fi.Length; } catch { }
            if (Cache.TryGetValue(path, out var c) && c.stamp == stamp) return c.info;
            var info = Compute(path);
            if (Cache.Count > 20000) Cache.Clear();
            Cache[path] = (stamp, info);
            return info;
        }

        static TrustInfo Compute(string path)
        {
            var t = new TrustInfo();
            try
            {
                t.Status = VerifyEmbedded(path);
                t.Embedded = t.Status != 0x800B0100;     // TRUST_E_NOSIGNATURE
                if (t.Embedded)
                {
                    try
                    {
#pragma warning disable SYSLIB0057
                        using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
                        t.Subject = cert.Subject;
                        t.Publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
                    }
                    catch { }
                }
                if (t.Status == 0) { t.Valid = true; return t; }
                if (!t.Embedded && InCatalog(path)) { t.Valid = true; t.Catalog = true; t.Publisher = "Microsoft Windows"; }
            }
            catch { }
            return t;
        }

        static uint VerifyEmbedded(string path)
        {
            Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");   // WINTRUST_ACTION_GENERIC_VERIFY_V2
            IntPtr pPath = Marshal.StringToHGlobalUni(path);
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            try
            {
                Marshal.StructureToPtr(new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = pPath }, pFile, false);
                var d = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = 2,              // WTD_UI_NONE
                    fdwRevocationChecks = 0,     // WTD_REVOKE_NONE: never touches the network
                    dwUnionChoice = 1,           // WTD_CHOICE_FILE
                    pFile = pFile,
                    dwStateAction = 1,           // WTD_STATEACTION_VERIFY
                    dwProvFlags = 0x1000 | 0x10, // cache-only URL retrieval, no revocation check
                };
                uint r = WinVerifyTrust(IntPtr.Zero, ref action, ref d);
                d.dwStateAction = 2;             // WTD_STATEACTION_CLOSE
                WinVerifyTrust(IntPtr.Zero, ref action, ref d);
                return r;
            }
            finally { Marshal.FreeHGlobal(pFile); Marshal.FreeHGlobal(pPath); }
        }

        static bool InCatalog(string path)
        {
            if (!CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0)) return false;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                uint cb = 64; var hash = new byte[cb];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle, ref cb, hash, 0)) return false;
                IntPtr cat = CryptCATAdminEnumCatalogFromHash(admin, hash, cb, 0, IntPtr.Zero);
                if (cat == IntPtr.Zero) return false;
                CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                return true;
            }
            catch { return false; }
            finally { CryptCATAdminReleaseContext(admin, 0); }
        }
    }
}
