# -*- coding: utf-8 -*-
"""Sour static-PE feature specification.

One definition, two implementations:
  * here  : features computed from an EMBER2024 raw JSON record (training)
  * C#    : src/Sour/Av/PeFeatures.cs computes the same vector from a file (inference)

tools/verify_features.py checks that both agree on real local PE files
(thrember -> JSON -> this module  versus  Sour.exe --features).
Keep the ORDER of FEATURE_NAMES identical to PeFeatures.Names in C#.
"""
import math

STD_SECTIONS = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".edata",
    ".tls", ".bss", ".xdata", "CODE", "DATA", "BSS", ".didat", ".CRT", ".gfids",
    ".00cfg", ".debug", "INIT", "PAGE", ".orpc", ".sdata", ".ndata",
}

COFF_FLAGS = ["RELOCS_STRIPPED", "EXECUTABLE_IMAGE", "LINE_NUMS_STRIPPED",
              "LOCAL_SYMS_STRIPPED", "LARGE_ADDRESS_AWARE", "32BIT_MACHINE",
              "DEBUG_STRIPPED", "SYSTEM", "DLL"]

DLL_FLAGS = ["HIGH_ENTROPY_VA", "DYNAMIC_BASE", "FORCE_INTEGRITY", "NX_COMPAT",
             "NO_ISOLATION", "NO_SEH", "NO_BIND", "APPCONTAINER", "WDM_DRIVER",
             "GUARD_CF", "TERMINAL_SERVER_AWARE"]

OPT_NUM = ["major_image_version", "minor_image_version", "major_linker_version",
           "minor_linker_version", "major_operating_system_version",
           "minor_operating_system_version", "major_subsystem_version",
           "minor_subsystem_version"]

OPT_LOG = ["sizeof_code", "sizeof_headers", "sizeof_image", "sizeof_initialized_data",
           "sizeof_uninitialized_data", "sizeof_stack_reserve", "sizeof_stack_commit",
           "sizeof_heap_reserve", "sizeof_heap_commit", "address_of_entrypoint",
           "base_of_code", "image_base", "section_alignment"]

IMPORT_DLLS = ["kernel32", "user32", "advapi32", "ntdll", "wininet", "winhttp",
               "ws2_32", "wsock32", "urlmon", "shell32", "crypt32", "mscoree",
               "msvbvm60", "psapi", "shlwapi", "ole32", "gdi32", "netapi32",
               "iphlpapi", "wtsapi32", "dnsapi", "bcrypt", "msvcrt", "vcruntime140"]

IMPORT_APIS = ["VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
               "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
               "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
               "ResumeThread", "OpenProcess", "CreateProcess", "ShellExecute",
               "WinExec", "LoadLibrary", "GetProcAddress", "IsDebuggerPresent",
               "CheckRemoteDebuggerPresent", "SetWindowsHookEx", "GetAsyncKeyState",
               "GetForegroundWindow", "RegSetValueEx", "RegCreateKeyEx",
               "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
               "InternetOpen", "InternetOpenUrl", "InternetReadFile",
               "URLDownloadToFile", "HttpSendRequest", "WSAStartup", "connect",
               "CreateService", "StartService", "AdjustTokenPrivileges",
               "OpenProcessToken", "CreateToolhelp32Snapshot", "Process32Next",
               "FindFirstFile", "DeleteFile", "MoveFileEx", "CreateFile",
               "WriteFile", "GetTickCount", "Sleep", "TerminateProcess",
               "CreateMutex", "FindResource", "LoadResource", "_CorExeMain"]

DATADIRS = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
            "DEBUG", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT",
            "COM_DESCRIPTOR"]


def _names():
    n = ["size_log", "file_entropy"]
    n += [f"hist16_{i}" for i in range(16)]
    n += ["frac_zero", "frac_ff", "frac_printable"]
    n += ["str_num_log", "str_avlen", "str_printable_frac", "str_entropy"]
    n += ["coff_timestamp", "machine_amd64", "machine_i386", "n_sections",
          "n_symbols_log", "sizeof_opt_header", "has_symtab"]
    n += [f"coff_{f}" for f in COFF_FLAGS]
    n += ["magic_pe32plus", "subsys_gui", "subsys_cui", "subsys_native"]
    n += [f"opt_{f}" for f in OPT_NUM]
    n += [f"opt_{f}_log" for f in OPT_LOG]
    n += ["checksum_zero", "n_rvas", "e_lfanew"]
    n += [f"dllchar_{f}" for f in DLL_FLAGS]
    n += ["sec_zero_size", "sec_high_entropy", "sec_mean_entropy", "sec_max_entropy",
          "sec_min_entropy", "sec_exec", "sec_write", "sec_wx", "sec_empty_name",
          "sec_nonstd_name", "sec_raw_frac", "sec_max_vratio_log",
          "entry_is_text", "entry_std_name", "entry_entropy", "entry_writable",
          "entry_missing"]
    n += ["overlay_size_log", "overlay_ratio", "overlay_entropy"]
    n += ["imp_n_dll", "imp_n_func_log"]
    n += [f"dll_{d}" for d in IMPORT_DLLS]
    n += [f"api_{a}" for a in IMPORT_APIS]
    n += ["exp_n_log"]
    n += [f"dd_{d}_log" for d in DATADIRS]
    n += ["rich_n_log"]
    return n


FEATURE_NAMES = _names()
N_FEATURES = len(FEATURE_NAMES)


def lg(x):
    try:
        x = float(x)
    except (TypeError, ValueError):
        return 0.0
    return math.log1p(x) if x > 0 else 0.0


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def entropy_counts(counts):
    tot = float(sum(counts))
    if tot <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / tot
            h -= p * math.log2(p)
    return h


def features_from_json(d):
    """EMBER2024 raw record -> list[float] of length N_FEATURES."""
    f = []
    gen = d.get("general") or {}
    size = max(num(gen.get("size")), 1.0)
    hist = d.get("histogram") or [0] * 256
    if len(hist) != 256:
        hist = [0] * 256
    f.append(lg(size))
    f.append(entropy_counts(hist))
    for i in range(16):
        f.append(sum(hist[i * 16:(i + 1) * 16]) / size)
    f.append(hist[0] / size)
    f.append(hist[255] / size)
    f.append(sum(hist[32:127]) / size)

    st = d.get("strings") or {}
    f.append(lg(st.get("numstrings")))
    f.append(num(st.get("avlength")))
    f.append(num(st.get("printables")) / size)
    f.append(num(st.get("entropy")))

    hdr = d.get("header") or {}
    coff = hdr.get("coff") or {}
    opt = hdr.get("optional") or {}
    dos = hdr.get("dos") or {}
    mach = str(coff.get("machine") or "")
    f.append(num(coff.get("timestamp")))
    f.append(1.0 if mach.endswith("AMD64") else 0.0)
    f.append(1.0 if mach.endswith("I386") else 0.0)
    f.append(num(coff.get("number_of_sections")))
    f.append(lg(coff.get("number_of_symbols")))
    f.append(num(coff.get("sizeof_optional_header")))
    f.append(1.0 if num(coff.get("pointer_to_symbol_table")) > 0 else 0.0)
    ch = set(coff.get("characteristics") or [])
    for name in COFF_FLAGS:
        f.append(1.0 if name in ch else 0.0)

    sub = str(opt.get("subsystem") or "")
    f.append(1.0 if num(opt.get("magic")) == 523 else 0.0)
    f.append(1.0 if sub.endswith("WINDOWS_GUI") else 0.0)
    f.append(1.0 if sub.endswith("WINDOWS_CUI") else 0.0)
    f.append(1.0 if sub.endswith("SUBSYSTEM_NATIVE") else 0.0)
    for k in OPT_NUM:
        f.append(num(opt.get(k)))
    for k in OPT_LOG:
        f.append(lg(opt.get(k)))
    f.append(1.0 if num(opt.get("checksum")) == 0 else 0.0)
    f.append(num(opt.get("number_of_rvas_and_sizes")))
    f.append(num(dos.get("e_lfanew")))
    dc = set(opt.get("dll_characteristics") or [])
    for name in DLL_FLAGS:
        f.append(1.0 if name in dc else 0.0)

    sec = d.get("section") or {}
    secs = sec.get("sections") or []
    ents = [num(s.get("entropy")) for s in secs]
    n_zero = n_high = n_exec = n_write = n_wx = n_empty = n_nonstd = 0
    raw_sum = 0.0
    max_vr = 0.0
    for s in secs:
        props = set(s.get("props") or [])
        sz = num(s.get("size"))
        vs = num(s.get("vsize"))
        nm = str(s.get("name") or "")
        raw_sum += sz
        if sz == 0:
            n_zero += 1
        if num(s.get("entropy")) > 7.0:
            n_high += 1
        ex = "MEM_EXECUTE" in props
        wr = "MEM_WRITE" in props
        n_exec += ex
        n_write += wr
        n_wx += (ex and wr)
        if nm == "":
            n_empty += 1
        elif nm not in STD_SECTIONS:
            n_nonstd += 1
        max_vr = max(max_vr, vs / max(sz, 1.0))
    f.append(float(n_zero))
    f.append(float(n_high))
    f.append(sum(ents) / len(ents) if ents else 0.0)
    f.append(max(ents) if ents else 0.0)
    f.append(min(ents) if ents else 0.0)
    f.append(float(n_exec))
    f.append(float(n_write))
    f.append(float(n_wx))
    f.append(float(n_empty))
    f.append(float(n_nonstd))
    f.append(min(raw_sum / size, 4.0))
    f.append(lg(max_vr))
    entry = str(sec.get("entry") or "")
    es = None
    for s in secs:
        if str(s.get("name") or "") == entry:
            es = s
            break
    f.append(1.0 if entry == ".text" else 0.0)
    f.append(1.0 if entry in STD_SECTIONS else 0.0)
    f.append(num(es.get("entropy")) if es else 0.0)
    f.append(1.0 if es and "MEM_WRITE" in (es.get("props") or []) else 0.0)
    f.append(1.0 if es is None else 0.0)

    ov = sec.get("overlay") or {}
    f.append(lg(ov.get("size")))
    f.append(num(ov.get("size_ratio")))
    f.append(num(ov.get("entropy")))

    imps = d.get("imports") or {}
    if not isinstance(imps, dict):
        imps = {}
    dlls = [str(k).lower() for k in imps.keys()]
    funcs = set()
    nfunc = 0
    for v in imps.values():
        if isinstance(v, list):
            nfunc += len(v)
            for name in v:
                funcs.add(str(name))
    f.append(float(len(dlls)))
    f.append(lg(nfunc))
    for dn in IMPORT_DLLS:
        f.append(1.0 if any(x.startswith(dn) for x in dlls) else 0.0)
    for an in IMPORT_APIS:
        hit = (an in funcs) or (an + "A" in funcs) or (an + "W" in funcs)
        f.append(1.0 if hit else 0.0)

    ex = d.get("exports") or []
    f.append(lg(len(ex)))

    dd = {}
    for e in (d.get("datadirectories") or []):
        if isinstance(e, dict) and "name" in e:
            dd[str(e["name"])] = num(e.get("size"))
    for name in DATADIRS:
        f.append(lg(dd.get(name, 0.0)))

    rich = d.get("richheader") or []
    f.append(lg(len(rich) // 2))

    assert len(f) == N_FEATURES, (len(f), N_FEATURES)
    return f
