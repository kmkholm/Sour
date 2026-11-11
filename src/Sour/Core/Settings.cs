using System;
using System.Collections.Generic;

namespace Sour.Core
{
    public enum FwMode { Off, Monitor, Blocklist, Whitelist, Lockdown }
    public enum AvAction { Ask, Quarantine, ReportOnly }
    public enum AutoPilot { Off, Assist, Full }

    /// <summary>All user-tunable options. Saved as JSON in %LOCALAPPDATA%\Sour\settings.json.</summary>
    public sealed class Settings
    {
        public string Language = "ar";

        // ---- firewall
        public FwMode FirewallMode = FwMode.Off;
        public bool FwPersistent = true;            // filters stay enforced while Sour is closed / after reboot
        public bool FwBlockInbound = true;          // stealth: drop unsolicited inbound except allowed apps
        public bool FwAllowCoreServices = true;     // DNS, DHCP, NTP, ICMPv6 neighbour discovery
        public bool FwAllowLan = true;              // private ranges stay reachable in whitelist mode
        public bool FwHashPinning = true;           // re-ask when an allowed binary changes on disk
        public bool FwTrustMicrosoft = true;        // auto-allow binaries signed by Microsoft
        public AutoPilot FwAutoPilot = AutoPilot.Assist;
        public bool FwAuditEvents = true;           // enable WFP connection auditing to see blocked attempts
        public int FwTempRuleMinutes = 60;

        // ---- antivirus
        public bool AvRealtime = false;
        public bool AvProcessWatch = false;
        public bool AvRansomShield = false;
        public bool AvUsbScan = true;
        public bool AvPersistenceWatch = true;
        public bool AvUseAmsi = true;               // second opinion from the installed AMSI provider
        public bool AvUseMl = true;
        public bool AvScanArchives = true;
        public AvAction AvOnMalicious = AvAction.Ask;
        public double AvMlMalicious = 0.0;          // 0 = use thresholds from the model card
        public double AvMlSuspicious = 0.0;
        public int AvMaxFileMb = 256;
        public List<string> AvExclusions = new List<string>();
        public List<string> AvWatchFolders = new List<string>();   // empty = defaults (Downloads, Desktop, Documents, Temp, Startup)

        // ---- network AI
        public bool NetAi = true;
        public double NetAiAlertScore = 60;        // 0..100
        public int NetAiLearnConnections = 30;      // per app before anomalies are raised

        public bool StartMinimized = false;
        public int ScheduledScanHour = -1;          // daily quick scan at this hour; -1 = off
        public string LastScheduledScan = "";
        public bool ExplorerMenu = false;           // "Scan with Sour" in the Explorer right-click menu
        public bool Notifications = true;

        static Settings _cur;
        public static Settings Current => _cur ??= Json.Load<Settings>(Paths.SettingsFile);
        public static void Save() { try { Json.Save(Paths.SettingsFile, Current); } catch (Exception ex) { Log.Debug("settings save: " + ex.Message); } }
        public static void Reload() { _cur = null; }
    }

    /// <summary>Two-language text helper: every UI string is written once as (English, Arabic).</summary>
    public static class I18n
    {
        public static bool IsArabic => Settings.Current.Language == "ar";
        public static event Action Changed;
        public static string T(string en, string ar) => IsArabic ? ar : en;
        public static void Set(string lang)
        {
            Settings.Current.Language = lang == "ar" ? "ar" : "en";
            Settings.Save();
            Changed?.Invoke();
        }
        public static void Toggle() => Set(IsArabic ? "en" : "ar");
    }
}
