using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Sour.Core;

namespace Sour.Fw
{
    public sealed class Conn
    {
        public int Pid; public string ProcessPath; public string ProcessName;
        public string Protocol;               // TCP / UDP
        public IPAddress Local; public int LocalPort;
        public IPAddress Remote; public int RemotePort;
        public string State; public string Host;      // host name from the local DNS cache, if known
        public DateTime FirstSeen = DateTime.Now;
        public double Risk;                   // 0..100 from the network AI
        public string RiskWhy;
        public string Key => $"{Pid}|{Protocol}|{Remote}|{RemotePort}";
        public bool IsListener => Remote == null || State == "LISTEN";
    }

    /// <summary>Live per-process connection table (IP Helper API). Works without administrator rights.</summary>
    public sealed class ConnMonitor
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder name, ref int size);

        const int AF_INET = 2, AF_INET6 = 23, TCP_TABLE_OWNER_PID_ALL = 5, UDP_TABLE_OWNER_PID = 1;
        static readonly string[] TcpStates = { "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB" };

        static readonly ConcurrentDictionary<int, (string path, DateTime at)> PathCache = new ConcurrentDictionary<int, (string, DateTime)>();

        public static string ProcessPath(int pid)
        {
            if (pid == 0) return "System Idle";
            if (pid == 4) return "System";
            if (PathCache.TryGetValue(pid, out var c) && (DateTime.Now - c.at).TotalSeconds < 30) return c.path;
            string path = null;
            IntPtr h = OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, false, pid);
            if (h != IntPtr.Zero)
            {
                try { var sb = new StringBuilder(1024); int n = sb.Capacity; if (QueryFullProcessImageName(h, 0, sb, ref n)) path = sb.ToString(); }
                finally { CloseHandle(h); }
            }
            if (path == null) { try { path = Process.GetProcessById(pid).ProcessName; } catch { path = "pid " + pid; } }
            if (PathCache.Count > 5000) PathCache.Clear();
            PathCache[pid] = (path, DateTime.Now);
            return path;
        }

        static ushort Port(uint raw) => (ushort)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

        static IntPtr Fetch(Func<IntPtr, int, (uint r, int size)> call)
        {
            int size = 0;
            var (r, need) = call(IntPtr.Zero, size);
            size = need;
            for (int i = 0; i < 4; i++)
            {
                IntPtr buf = Marshal.AllocHGlobal(size + 4096);
                var res = call(buf, size + 4096);
                if (res.r == 0) return buf;
                Marshal.FreeHGlobal(buf);
                size = res.size;
            }
            return IntPtr.Zero;
        }

        /// <summary>One snapshot of every TCP connection/listener and UDP endpoint with its owning process.</summary>
        public static List<Conn> Snapshot()
        {
            var list = new List<Conn>();
            // ---- TCP v4: MIB_TCPROW_OWNER_PID { state, localAddr, localPort, remoteAddr, remotePort, pid } = 24 bytes
            IntPtr p = Fetch((b, s) => { uint r = GetExtendedTcpTable(b, ref s, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); return (r, s); });
            if (p != IntPtr.Zero)
            {
                try
                {
                    int n = Marshal.ReadInt32(p);
                    for (int i = 0; i < n; i++)
                    {
                        IntPtr row = p + 4 + i * 24;
                        int state = Marshal.ReadInt32(row);
                        var c = new Conn
                        {
                            Protocol = "TCP", State = state >= 0 && state < TcpStates.Length ? TcpStates[state] : state.ToString(),
                            Local = new IPAddress((uint)Marshal.ReadInt32(row, 4)), LocalPort = Port((uint)Marshal.ReadInt32(row, 8)),
                            Remote = new IPAddress((uint)Marshal.ReadInt32(row, 12)), RemotePort = Port((uint)Marshal.ReadInt32(row, 16)),
                            Pid = Marshal.ReadInt32(row, 20),
                        };
                        if (state == 2) { c.Remote = null; c.RemotePort = 0; }
                        list.Add(c);
                    }
                }
                finally { Marshal.FreeHGlobal(p); }
            }
            // ---- TCP v6: MIB_TCP6ROW_OWNER_PID { localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid } = 56 bytes
            p = Fetch((b, s) => { uint r = GetExtendedTcpTable(b, ref s, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0); return (r, s); });
            if (p != IntPtr.Zero)
            {
                try
                {
                    int n = Marshal.ReadInt32(p);
                    for (int i = 0; i < n; i++)
                    {
                        IntPtr row = p + 4 + i * 56;
                        var la = new byte[16]; var ra = new byte[16];
                        Marshal.Copy(row, la, 0, 16); Marshal.Copy(row + 24, ra, 0, 16);
                        int state = Marshal.ReadInt32(row, 48);
                        var c = new Conn
                        {
                            Protocol = "TCP", State = state >= 0 && state < TcpStates.Length ? TcpStates[state] : state.ToString(),
                            Local = new IPAddress(la), LocalPort = Port((uint)Marshal.ReadInt32(row, 20)),
                            Remote = new IPAddress(ra), RemotePort = Port((uint)Marshal.ReadInt32(row, 44)),
                            Pid = Marshal.ReadInt32(row, 52),
                        };
                        if (state == 2) { c.Remote = null; c.RemotePort = 0; }
                        list.Add(c);
                    }
                }
                finally { Marshal.FreeHGlobal(p); }
            }
            // ---- UDP v4: MIB_UDPROW_OWNER_PID { localAddr, localPort, pid } = 12 bytes
            p = Fetch((b, s) => { uint r = GetExtendedUdpTable(b, ref s, false, AF_INET, UDP_TABLE_OWNER_PID, 0); return (r, s); });
            if (p != IntPtr.Zero)
            {
                try
                {
                    int n = Marshal.ReadInt32(p);
                    for (int i = 0; i < n; i++)
                    {
                        IntPtr row = p + 4 + i * 12;
                        list.Add(new Conn { Protocol = "UDP", State = "LISTEN", Local = new IPAddress((uint)Marshal.ReadInt32(row)), LocalPort = Port((uint)Marshal.ReadInt32(row, 4)), Pid = Marshal.ReadInt32(row, 8) });
                    }
                }
                finally { Marshal.FreeHGlobal(p); }
            }
            foreach (var c in list)
            {
                c.ProcessPath = ProcessPath(c.Pid);
                c.ProcessName = System.IO.Path.GetFileName(c.ProcessPath);
            }
            return list;
        }

        // ---------------- polling loop
        readonly Dictionary<string, Conn> _known = new Dictionary<string, Conn>();
        Timer _timer;
        public event Action<Conn> NewConnection;
        public event Action Updated;
        public List<Conn> Current { get; private set; } = new List<Conn>();
        public long TotalSeen;

        public void Start(int periodMs = 2000)
        {
            _timer ??= new Timer(_ => { try { Tick(); } catch (Exception ex) { Log.Debug("conn tick: " + ex.Message); } }, null, 500, periodMs);
        }
        public void Stop() { _timer?.Dispose(); _timer = null; }

        int _busy;
        public void Tick()
        {
            if (Interlocked.Exchange(ref _busy, 1) == 1) return;
            try
            {
                var snap = Snapshot();
                var hosts = DnsCache.Map();
                var nowKeys = new HashSet<string>();
                foreach (var c in snap)
                {
                    if (c.Remote != null && hosts.TryGetValue(c.Remote.ToString(), out string h)) c.Host = h;
                    if (c.IsListener) continue;
                    if (IPAddress.IsLoopback(c.Remote)) continue;
                    nowKeys.Add(c.Key);
                    if (_known.TryGetValue(c.Key, out var old)) { c.FirstSeen = old.FirstSeen; c.Risk = old.Risk; c.RiskWhy = old.RiskWhy; }
                    else
                    {
                        TotalSeen++;
                        try { NewConnection?.Invoke(c); } catch { }
                    }
                    _known[c.Key] = c;
                }
                foreach (var k in _known.Keys.Where(k => !nowKeys.Contains(k)).ToList()) _known.Remove(k);
                Current = snap;
                Updated?.Invoke();
            }
            finally { Interlocked.Exchange(ref _busy, 0); }
        }
    }

    /// <summary>IP → host name map read from the Windows DNS resolver cache (no queries leave the machine).</summary>
    public static class DnsCache
    {
        [StructLayout(LayoutKind.Sequential)]
        struct DNS_CACHE_ENTRY { public IntPtr pNext; public IntPtr pszName; public ushort wType; public ushort wDataLength; public uint dwFlags; }

        [DllImport("dnsapi.dll")] static extern bool DnsGetCacheDataTable(out IntPtr table);
        [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)] static extern int DnsQuery_W(string name, ushort type, uint options, IntPtr extra, out IntPtr records, IntPtr reserved);
        [DllImport("dnsapi.dll")] static extern void DnsRecordListFree(IntPtr list, int freeType);
        [DllImport("dnsapi.dll")] static extern void DnsFree(IntPtr p, int freeType);

        static Dictionary<string, string> _map = new Dictionary<string, string>();
        static DateTime _at = DateTime.MinValue;
        static readonly object Gate = new object();

        public static List<string> Names()
        {
            var names = new List<string>();
            try
            {
                if (!DnsGetCacheDataTable(out IntPtr table) || table == IntPtr.Zero) return names;
                try
                {
                    for (IntPtr cur = table; cur != IntPtr.Zero;)
                    {
                        var e = Marshal.PtrToStructure<DNS_CACHE_ENTRY>(cur);
                        if (e.pszName != IntPtr.Zero && (e.wType == 1 || e.wType == 28 || e.wType == 5))
                            names.Add(Marshal.PtrToStringUni(e.pszName));
                        cur = e.pNext;
                    }
                }
                finally { DnsRecordListFree(table, 1); }   // the table has the DNS_RECORD list layout (next, name)
            }
            catch { }
            return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static Dictionary<string, string> Map()
        {
            lock (Gate)
            {
                if ((DateTime.Now - _at).TotalSeconds < 20) return _map;
                var m = new Dictionary<string, string>();
                try
                {
                    foreach (string name in Names().Take(600))
                    {
                        foreach (ushort type in new ushort[] { 1, 28 })
                        {
                            // DNS_QUERY_NO_WIRE_QUERY (0x10): answer from the cache only
                            if (DnsQuery_W(name, type, 0x10, IntPtr.Zero, out IntPtr rec, IntPtr.Zero) != 0 || rec == IntPtr.Zero) continue;
                            try
                            {
                                for (IntPtr r = rec; r != IntPtr.Zero; r = Marshal.ReadIntPtr(r))
                                {
                                    ushort t = (ushort)Marshal.ReadInt16(r, 16);
                                    if (t == 1) { var b = new byte[4]; Marshal.Copy(r + 32, b, 0, 4); m[new IPAddress(b).ToString()] = name; }
                                    else if (t == 28) { var b = new byte[16]; Marshal.Copy(r + 32, b, 0, 16); m[new IPAddress(b).ToString()] = name; }
                                }
                            }
                            finally { DnsRecordListFree(rec, 1); }
                        }
                    }
                }
                catch { }
                _map = m; _at = DateTime.Now;
                return m;
            }
        }
    }
}
