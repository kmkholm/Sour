using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Sour.Core;

namespace Sour.Fw
{
    public enum RuleAction { Allow, Block }

    public sealed class AppRule
    {
        public string Id = Guid.NewGuid().ToString("N");
        public string Path;
        public string Name;
        public RuleAction Action;
        public bool Enabled = true;
        public bool AllowInbound;            // also accept unsolicited inbound (servers, P2P)
        public ushort? RemotePort;           // optional narrowing of an Allow rule
        public byte? Protocol;
        public string Hash;                  // SHA-256 at approval time (hash pinning)
        public string Publisher;
        public bool HashChanged;             // binary differs from the approved one: rule suspended
        public string Source = "user";       // user | autopilot | trusted
        public string Note;
        public DateTime Created = DateTime.Now;
        public DateTime? Expires;            // temporary rule
    }

    public sealed class IpRule
    {
        public string Cidr; public string Note; public bool Enabled = true;
    }

    public sealed class RuleStore
    {
        public List<AppRule> Apps = new List<AppRule>();
        public List<IpRule> BlockedIps = new List<IpRule>();
        public List<ulong> ActiveFilterIds = new List<ulong>();   // runtime ids of the filters currently installed
        public bool AuditEnabledBySour;

        static RuleStore _cur;
        public static RuleStore Current => _cur ??= Json.Load<RuleStore>(Paths.RulesFile);
        public static void Save() { try { Json.Save(Paths.RulesFile, Current); } catch (Exception ex) { Log.Debug("rules save: " + ex.Message); } }
        public static void Reload() { _cur = null; }

        public AppRule Find(string path) =>
            Apps.FirstOrDefault(r => string.Equals(r.Path, path, StringComparison.OrdinalIgnoreCase));
    }

    public sealed class ApplyResult
    {
        public bool Ok; public string Error; public int Installed, SkippedMissing, Removed;
        public override string ToString() => Ok ? $"ok: {Installed} filters installed ({Removed} replaced, {SkippedMissing} skipped: file missing)" : "failed: " + Error;
    }

    /// <summary>
    /// Turns the rule store + settings into WFP filters. Weights inside the Sour sublayer:
    /// 15 explicit app block · 14 loopback permit · 13 IP blocklist · 10 app permit · 9 core services · 8 LAN · 1 default block.
    /// </summary>
    public static class FirewallEngine
    {
        public const byte WBlockApp = 15, WLoopback = 14, WBlockIp = 13, WAllowApp = 10, WCore = 9, WLan = 8, WDefault = 1;

        public static event Action Changed;

        // ---------- CIDR helpers
        public static bool TryParseCidr(string text, out IPAddress addr, out int prefix)
        {
            addr = null; prefix = 0;
            if (string.IsNullOrWhiteSpace(text)) return false;
            text = text.Trim();
            string ip = text; string pre = null;
            int slash = text.IndexOf('/');
            if (slash > 0) { ip = text.Substring(0, slash); pre = text.Substring(slash + 1); }
            if (!IPAddress.TryParse(ip, out addr)) return false;
            int max = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            prefix = max;
            if (pre != null && (!int.TryParse(pre, out prefix) || prefix < 0 || prefix > max)) return false;
            return true;
        }

        static uint V4Host(IPAddress a) { var b = a.GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
        static uint V4Mask(int prefix) => prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);

        static FilterSpec IpSpec(string name, bool outbound, bool block, byte weight, IPAddress a, int prefix)
        {
            var f = new FilterSpec { Name = name, Outbound = outbound, Block = block, Weight = weight };
            if (a.AddressFamily == AddressFamily.InterNetwork) { f.V4Addr = V4Host(a) & V4Mask(prefix); f.V4Mask = V4Mask(prefix); }
            else { f.V6 = true; f.V6Addr = a.GetAddressBytes(); f.V6Prefix = (byte)prefix; }
            return f;
        }

        static IEnumerable<FilterSpec> Both(FilterSpec f)
        {
            // an address-less spec applies to IPv4 and IPv6
            yield return f;
            yield return new FilterSpec
            {
                Name = f.Name, Outbound = f.Outbound, Block = f.Block, Weight = f.Weight, AppPath = f.AppPath, Loopback = f.Loopback,
                Protocol = f.Protocol, RemotePort = f.RemotePort, LocalPort = f.LocalPort, V6 = true,
            };
        }

        /// <summary>Pure function: which filters the current policy needs. Unit-tested without administrator rights.</summary>
        public static List<FilterSpec> BuildSpecs(Settings s, RuleStore store, DateTime now)
        {
            var specs = new List<FilterSpec>();
            if (s.FirewallMode == FwMode.Off || s.FirewallMode == FwMode.Monitor) return specs;

            // loopback is never filtered: local IPC must keep working in every mode
            specs.AddRange(Both(new FilterSpec { Name = "loopback", Outbound = true, Weight = WLoopback, Loopback = true }));
            specs.AddRange(Both(new FilterSpec { Name = "loopback in", Outbound = false, Weight = WLoopback, Loopback = true }));

            if (s.FirewallMode == FwMode.Lockdown)
            {
                specs.AddRange(Both(new FilterSpec { Name = "lockdown out", Outbound = true, Block = true, Weight = WDefault }));
                specs.AddRange(Both(new FilterSpec { Name = "lockdown in", Outbound = false, Block = true, Weight = WDefault }));
                return specs;
            }

            var live = store.Apps.Where(r => r.Enabled && !string.IsNullOrEmpty(r.Path) && (r.Expires == null || r.Expires > now)).ToList();

            foreach (var r in live.Where(r => r.Action == RuleAction.Block))
            {
                specs.AddRange(Both(new FilterSpec { Name = "block " + r.Name, Outbound = true, Block = true, Weight = WBlockApp, AppPath = r.Path }));
                specs.AddRange(Both(new FilterSpec { Name = "block in " + r.Name, Outbound = false, Block = true, Weight = WBlockApp, AppPath = r.Path }));
            }

            foreach (var ip in store.BlockedIps.Where(i => i.Enabled))
            {
                if (!TryParseCidr(ip.Cidr, out var a, out int p)) continue;
                specs.Add(IpSpec("ip block " + ip.Cidr, true, true, WBlockIp, a, p));
                specs.Add(IpSpec("ip block in " + ip.Cidr, false, true, WBlockIp, a, p));
            }

            bool whitelist = s.FirewallMode == FwMode.Whitelist;
            var allowed = live.Where(r => r.Action == RuleAction.Allow && !r.HashChanged).ToList();

            if (whitelist)
            {
                foreach (var r in allowed)
                    specs.AddRange(Both(new FilterSpec { Name = "allow " + r.Name, Outbound = true, Weight = WAllowApp, AppPath = r.Path, RemotePort = r.RemotePort, Protocol = r.Protocol }));

                if (s.FwAllowCoreServices)
                {
                    specs.AddRange(Both(new FilterSpec { Name = "core dns udp", Weight = WCore, Protocol = 17, RemotePort = 53 }));
                    specs.AddRange(Both(new FilterSpec { Name = "core dns tcp", Weight = WCore, Protocol = 6, RemotePort = 53 }));
                    specs.Add(new FilterSpec { Name = "core dhcp", Weight = WCore, Protocol = 17, RemotePort = 67 });
                    specs.Add(new FilterSpec { Name = "core dhcpv6", Weight = WCore, Protocol = 17, RemotePort = 547, V6 = true });
                    specs.AddRange(Both(new FilterSpec { Name = "core ntp", Weight = WCore, Protocol = 17, RemotePort = 123 }));
                    specs.Add(new FilterSpec { Name = "core icmp", Weight = WCore, Protocol = 1 });
                    specs.Add(new FilterSpec { Name = "core icmpv6", Weight = WCore, Protocol = 58, V6 = true });
                }
                if (s.FwAllowLan)
                {
                    foreach (string c in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "ff00::/8", "fc00::/7" })
                    {
                        TryParseCidr(c, out var a, out int p);
                        specs.Add(IpSpec("lan " + c, true, false, WLan, a, p));
                    }
                }
                specs.AddRange(Both(new FilterSpec { Name = "default deny out", Outbound = true, Block = true, Weight = WDefault }));
            }

            if (s.FwBlockInbound)
            {
                foreach (var r in allowed.Where(r => r.AllowInbound))
                    specs.AddRange(Both(new FilterSpec { Name = "allow in " + r.Name, Outbound = false, Weight = WAllowApp, AppPath = r.Path }));
                if (s.FwAllowCoreServices)
                {
                    specs.Add(new FilterSpec { Name = "core dhcp in", Outbound = false, Weight = WCore, Protocol = 17, LocalPort = 68 });
                    specs.Add(new FilterSpec { Name = "core dhcpv6 in", Outbound = false, Weight = WCore, Protocol = 17, LocalPort = 546, V6 = true });
                    specs.Add(new FilterSpec { Name = "core icmpv6 in", Outbound = false, Weight = WCore, Protocol = 58, V6 = true });
                }
                specs.AddRange(Both(new FilterSpec { Name = "stealth inbound", Outbound = false, Block = true, Weight = WDefault }));
            }
            return specs;
        }

        /// <summary>Installs the policy atomically (one WFP transaction). Requires administrator rights.</summary>
        public static ApplyResult Apply()
        {
            var s = Settings.Current; var store = RuleStore.Current;
            var res = new ApplyResult();
            try
            {
                PruneExpired();
                if (s.FwHashPinning) VerifyPins(false);
                var specs = BuildSpecs(s, store, DateTime.Now);
                using var wfp = new Wfp();
                wfp.Begin();
                try
                {
                    if (specs.Count == 0)
                    {
                        res.Removed = wfp.RemoveEverything();
                        store.ActiveFilterIds.Clear();
                    }
                    else
                    {
                        wfp.EnsureProviderAndSubLayer(s.FwPersistent);
                        res.Removed = wfp.DeleteOwnFilters();
                        var ids = new List<ulong>();
                        foreach (var f in specs)
                        {
                            ulong id = wfp.AddFilter(f, s.FwPersistent);
                            if (id == 0) res.SkippedMissing++; else { ids.Add(id); res.Installed++; }
                        }
                        store.ActiveFilterIds = ids;
                    }
                    wfp.Commit();
                }
                catch { wfp.Abort(); throw; }
                res.Ok = true;
                RuleStore.Save();
                if (s.FirewallMode != FwMode.Off && s.FwAuditEvents) EnableAudit(true);
                if (s.FirewallMode == FwMode.Off) EnableAudit(false);
                Log.Add(EventKind.Firewall, Severity.Info, "fw.applied",
                    $"Firewall policy applied: {s.FirewallMode}", $"تم تطبيق سياسة الجدار الناري: {ModeAr(s.FirewallMode)}", res.ToString());
            }
            catch (Exception ex)
            {
                res.Ok = false; res.Error = ex.Message;
                Log.Add(EventKind.Firewall, Severity.High, "fw.apply_failed", "Firewall policy could not be applied", "تعذّر تطبيق سياسة الجدار الناري", ex.Message);
            }
            Changed?.Invoke();
            return res;
        }

        /// <summary>Emergency off: deletes every Sour object from the filtering engine.</summary>
        public static ApplyResult RemoveAll()
        {
            var res = new ApplyResult();
            try
            {
                using var wfp = new Wfp();
                res.Removed = wfp.RemoveEverything();
                RuleStore.Current.ActiveFilterIds.Clear(); RuleStore.Save();
                EnableAudit(false);
                res.Ok = true;
            }
            catch (Exception ex) { res.Error = ex.Message; }
            Changed?.Invoke();
            return res;
        }

        /// <summary>What is really installed right now (read from the engine, not from our own records).</summary>
        public static (bool ok, int count, string error) LiveState()
        {
            try { using var wfp = new Wfp(); return (true, wfp.EnumOwnFilters().Count, null); }
            catch (Exception ex) { return (false, 0, ex.Message); }
        }

        public static string ModeAr(FwMode m) => m switch
        {
            FwMode.Off => "متوقف", FwMode.Monitor => "مراقبة فقط", FwMode.Blocklist => "قائمة الحظر",
            FwMode.Whitelist => "القائمة البيضاء", FwMode.Lockdown => "إغلاق تام", _ => m.ToString(),
        };

        static void EnableAudit(bool on)
        {
            // "Filtering Platform Connection" subcategory, addressed by GUID so it works on every display language
            const string sub = "{0CCE9226-69AE-11D9-BED3-505054503030}";
            var store = RuleStore.Current;
            if (on)
            {
                var r = Util.Run("auditpol.exe", $"/set /subcategory:{sub} /failure:enable");
                if (r.code == 0) { store.AuditEnabledBySour = true; RuleStore.Save(); }
            }
            else if (store.AuditEnabledBySour)
            {
                Util.Run("auditpol.exe", $"/set /subcategory:{sub} /failure:disable");
                store.AuditEnabledBySour = false; RuleStore.Save();
            }
        }

        public static int PruneExpired()
        {
            var store = RuleStore.Current;
            int n = store.Apps.RemoveAll(r => r.Expires != null && r.Expires <= DateTime.Now);
            if (n > 0) RuleStore.Save();
            return n;
        }

        /// <summary>
        /// Hash pinning: an Allow rule is bound to the SHA-256 of the binary that was approved. If the file changes,
        /// the rule is suspended unless the new file carries a valid signature from the same publisher (normal updates).
        /// </summary>
        public static List<AppRule> VerifyPins(bool raiseEvents = true)
        {
            var changed = new List<AppRule>();
            foreach (var r in RuleStore.Current.Apps.Where(r => r.Action == RuleAction.Allow && !string.IsNullOrEmpty(r.Hash)))
            {
                try
                {
                    if (!File.Exists(r.Path)) continue;
                    string h = Util.Sha256(r.Path);
                    if (h == r.Hash) { r.HashChanged = false; continue; }
                    var t = Av.Trust.Check(r.Path);
                    if (t.Valid && !string.IsNullOrEmpty(r.Publisher) && string.Equals(t.Publisher, r.Publisher, StringComparison.OrdinalIgnoreCase))
                    {
                        r.Hash = h; r.HashChanged = false;      // legitimate update by the same signer: re-pin silently
                        continue;
                    }
                    if (!r.HashChanged)
                    {
                        r.HashChanged = true; changed.Add(r);
                        if (raiseEvents)
                            Log.Add(EventKind.Firewall, Severity.High, "fw.pin_changed",
                                "Allowed program changed on disk — rule suspended", "برنامج مسموح تغيّر على القرص — عُلّقت القاعدة",
                                $"{r.Path}\napproved sha256={r.Hash}\ncurrent  sha256={h}\nsigner now: {(t.Valid ? t.Publisher : "none/invalid")}", r.Path);
                    }
                }
                catch { }
            }
            if (changed.Count > 0) RuleStore.Save();
            return changed;
        }

        public static AppRule SetRule(string path, RuleAction action, string source = "user", int tempMinutes = 0, bool inbound = false)
        {
            var store = RuleStore.Current;
            var r = store.Find(path);
            if (r == null) { r = new AppRule { Path = path }; store.Apps.Add(r); }
            r.Name = System.IO.Path.GetFileName(path);
            r.Action = action; r.Enabled = true; r.Source = source; r.HashChanged = false; r.AllowInbound = inbound;
            r.Expires = tempMinutes > 0 ? DateTime.Now.AddMinutes(tempMinutes) : (DateTime?)null;
            try { if (File.Exists(path)) { r.Hash = Util.Sha256(path); var t = Av.Trust.Check(path); r.Publisher = t.Valid ? t.Publisher : null; } } catch { }
            RuleStore.Save();
            Changed?.Invoke();
            return r;
        }

        public static void RemoveRule(string id)
        {
            RuleStore.Current.Apps.RemoveAll(r => r.Id == id);
            RuleStore.Save(); Changed?.Invoke();
        }
    }

    /// <summary>Maps kernel device paths (\device\harddiskvolume3\...) to drive-letter paths.</summary>
    public static class DevicePaths
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

        static Dictionary<string, string> _map;
        static DateTime _built;

        static Dictionary<string, string> Map()
        {
            if (_map != null && (DateTime.Now - _built).TotalMinutes < 5) return _map;
            var m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in DriveInfo.GetDrives())
            {
                string letter = d.Name.TrimEnd('\\');
                var sb = new StringBuilder(512);
                if (QueryDosDevice(letter, sb, sb.Capacity) != 0) m[sb.ToString()] = letter;
            }
            _map = m; _built = DateTime.Now;
            return m;
        }

        public static string ToDos(string devicePath)
        {
            if (string.IsNullOrEmpty(devicePath) || !devicePath.StartsWith("\\device\\", StringComparison.OrdinalIgnoreCase)) return devicePath;
            foreach (var kv in Map())
                if (devicePath.StartsWith(kv.Key + "\\", StringComparison.OrdinalIgnoreCase))
                    return kv.Value + devicePath.Substring(kv.Key.Length);
            return devicePath;
        }
    }
}
