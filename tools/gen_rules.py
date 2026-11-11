# -*- coding: utf-8 -*-
"""Builds src/Sour/Data/rules.json.

Signature strings are malware indicators, so neither this source nor the generated file may contain
them verbatim (other scanners would flag the files). Here every literal is written with "~" marks
inside it, which are removed at build time; the output stores each pattern reversed ("r:" literals).

usage: python tools/gen_rules.py
"""
import json
import os

rules = []


def enc(text, nocase=True, wide=True):
    text = text.replace("~", "")
    return "r" + ("i" if nocase else "") + ("w" if wide else "") + ":" + text[::-1]


def g(*texts, cs=False, wide=True):
    return [enc(t, not cs, wide) for t in texts]


def R(id, score, target, en, ar, mitre, strings=None, min=0, unsigned=False, ext=None, imports=None, max_kb=0):
    d = dict(id=id, name=id.split(".", 1)[1], score=score, target=target, en=en, ar=ar, mitre=mitre, strings=strings or {}, min=min)
    if unsigned:
        d["unsigned_only"] = True
    if ext:
        d["ext"] = ext
    if imports:
        d["imports_all"] = [i.replace("~", "") for i in imports]
    if max_kb:
        d["max_kb"] = max_kb
    rules.append(d)


SCRIPT_EXT = [".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk"]

R("SOUR.Test.EICAR", 100, "any", "EICAR standard anti-malware test file (harmless)", "ملف الاختبار القياسي EICAR (غير ضار)", "",
  {"a": g("X5O!P%@AP[4\\PZX54(P^)7CC)7}$~EIC~AR-STAN~DARD-ANTI~VIRUS-TE~ST-FI~LE!$H+H*", cs=True, wide=False)}, max_kb=1)

R("SOUR.PS.DownloadExec", 85, "script", "PowerShell download-and-execute cradle", "سكربت PowerShell ينزّل شيفرة من الإنترنت وينفّذها مباشرة", "T1059.001",
  {"dl": g("down~loadstr~ing(", "down~loadfi~le(", "invoke-web~request", "net.web~client", "start-bits~transfer", "invoke-rest~method", "down~loadda~ta("),
   "exec": g("invoke-expr~ession", "ie~x(", "ie~x (", "|ie~x", "| ie~x", "ie~x $", ";ie~x ")})
R("SOUR.PS.EncodedCommand", 60, "any", "Launches PowerShell with an encoded (hidden) command", "تشغيل PowerShell بأمر مرمَّز لإخفاء محتواه", "T1027",
  {"ps": g("power~shell", "pwsh"), "enc": g(" -en~c ", "-encoded~command", " -e ja~b", " -e~c ", "frombase~64string(", " -e sq~b", " -en~c ja~b")}, ext=SCRIPT_EXT)
R("SOUR.PS.AmsiBypass", 90, "script", "Attempts to switch off the Antimalware Scan Interface (AMSI)", "محاولة تعطيل واجهة فحص البرمجيات الخبيثة AMSI", "T1562.001",
  {"a": g("am~si~init~fail~ed", "am~si~ut~ils", "am~si~scan~buf~fer")})
R("SOUR.NET.AmsiBypass", 70, "pe", "Binary carries AMSI-bypass markers", "ملف تنفيذي يحمل علامات تجاوز AMSI", "T1562.001",
  {"a": g("am~si~init~fail~ed")}, unsigned=True)
R("SOUR.Defender.Disable", 85, "script", "Disables Microsoft Defender protections", "تعطيل حمايات Microsoft Defender", "T1562.001",
  {"cmd": g("set-mp~pref~erence"), "opt": g("disable~realtime~monitoring", "disable~ioav~protection", "disable~behavior~monitoring", "disable~script~scanning", "disable~block~at~first~seen")})
R("SOUR.Defender.Exclusion", 60, "script", "Adds an antivirus exclusion from a script", "إضافة استثناء لمكافح الفيروسات من داخل سكربت", "T1562.001",
  {"cmd": g("add-mp~pref~erence"), "opt": g("-exclusion~path", "-exclusion~process", "-exclusion~extension")})
R("SOUR.Defender.RegistryKill", 35, "any", "Turns Defender off through policy registry values", "إيقاف Defender عبر قيم سجل السياسات", "T1562.001",
  {"a": g("disable~anti~spy~ware"), "b": g("windows defender")}, unsigned=True)
R("SOUR.Ransom.ShadowDelete", 75, "any", "Deletes Volume Shadow Copies / disables recovery (ransomware preparation)", "حذف النسخ الظلية وتعطيل الاستعادة (تمهيد لهجوم فدية)", "T1490",
  {"a": g("vss~admin del~ete sha~dows", "vss~admin.exe del~ete sha~dows", "wmic shadow~copy del~ete", "wb~admin del~ete cat~alog", "recovery~enabled no", "del~ete sha~dows /all", "win32_shadow~copy).del~ete")}, unsigned=True)
R("SOUR.Ransom.Note", 70, "any", "Contains ransom-note wording", "يحتوي عبارات رسالة فدية", "T1486",
  {"enc": g("your files have been encr~ypted", "all your files are encr~ypted", "files have been encr~ypted", "all of your files are encr~ypted", "your important files are encr~ypted"),
   "pay": g("bit~coin", ".on~ion", "decr~yptor", "decr~yption key", "ran~som", "decr~ypt your files")}, unsigned=True)
R("SOUR.Cred.Mimikatz", 95, "any", "Mimikatz credential-theft commands", "أوامر أداة سرقة كلمات المرور Mimikatz", "T1003.001",
  {"a": g("seku~rlsa::", "lsa~dump::", "invoke-mimi~katz", "kerberos::gol~den", "privi~lege::de~bug", "gentil~kiwi")}, unsigned=True)
R("SOUR.Shell.ReverseTcp", 85, "script", "PowerShell reverse shell over TCP", "صدفة عكسية عبر TCP بلغة PowerShell", "T1059.001",
  {"tcp": g("net.sockets.tcp~client"), "st": g("get~stream()"), "ex": g("invoke-expr~ession", "ie~x", "cmd.exe", "power~shell")})
R("SOUR.Shell.Netcat", 70, "script", "Netcat / bash reverse-shell one-liner", "أمر صدفة عكسية عبر netcat أو bash", "T1059",
  {"a": g("nc -e ", "nc.exe -e", "ncat -e", "/bin/sh -i", "bash -i >& /dev/t~cp/")})
R("SOUR.LOLBin.Download", 70, "any", "Uses a built-in Windows tool to fetch or run remote code", "استغلال أداة نظام مدمجة لتنزيل أو تنفيذ شيفرة بعيدة", "T1218",
  {"a": g("cert~util -url~cache", "cert~util.exe -url~cache", "bits~admin /trans~fer", "ms~hta http", "ms~hta.exe http", "regsvr~32 /s /n /u /i:http",
          "run~dll32 java~script:", "ms~hta vb~script:", "ms~hta java~script:", "run~dll32.exe java~script:")}, ext=SCRIPT_EXT)
R("SOUR.VBS.Dropper", 70, "script", "Script downloads a file and runs it (WScript dropper)", "سكربت ينزّل ملفاً ثم يشغّله (Dropper)", "T1059.005",
  {"sh": g("wscript.sh~ell", "shell.appli~cation"), "net": g("msxml2.xml~http", "msxml2.server~xmlhttp", "winhttp.winhttp~request", "adodb.str~eam"), "run": g(".run", "shell~execute", ".exec(")})
R("SOUR.Macro.AutoExec", 65, "any", "Office macro that runs commands when the document opens", "ماكرو أوفيس ينفّذ أوامر تلقائياً عند فتح المستند", "T1204.002",
  {"auto": g("auto~open", "document_~open", "workbook_~open", "auto_~open"), "act": g("shell(", "create~object(", "wscript.sh~ell", "power~shell")},
  ext=[".doc", ".xls", ".docm", ".xlsm", ".bin", ".dotm", ".ppt", ".pptm", ".xlam", ".bas"])
R("SOUR.Batch.HiddenRunKey", 55, "script", "Adds itself to startup and hides its file", "يضيف نفسه لبدء التشغيل ويخفي ملفه", "T1547.001",
  {"run": g("\\current~version\\run"), "hide": g("attrib +h", "attrib +s +h", "attrib +s")}, ext=[".bat", ".cmd"])
R("SOUR.Fw.Disable", 70, "any", "Switches Windows Firewall off", "إيقاف جدار حماية ويندوز", "T1562.004",
  {"a": g("netsh adv~firewall set all~profiles state off", "netsh fire~wall set op~mode disable", "set-net~firewall~profile -enabled false")}, ext=SCRIPT_EXT)
R("SOUR.Account.AddAdmin", 60, "script", "Creates a user and adds it to Administrators", "إنشاء مستخدم وإضافته لمجموعة المدراء", "T1136.001",
  {"a": g("net user "), "b": g(" /add"), "c": g("local~group admin~istrators")})
R("SOUR.Log.Clear", 60, "script", "Clears Windows event logs", "مسح سجلات أحداث ويندوز", "T1070.001",
  {"a": g("wevt~util cl ", "clear-event~log", "wevt~util.exe cl ")})
R("SOUR.C2.CobaltStrike", 90, "pe", "Cobalt Strike beacon markers", "علامات منارة Cobalt Strike", "S0154",
  {"rl": g("reflective~loader"), "bc": g("bea~con.dll", "bea~con.x64.dll", "%s as %s\\%s: %d", "could not spawn %s (token)")}, unsigned=True)
R("SOUR.C2.Meterpreter", 90, "pe", "Metasploit Meterpreter payload markers", "علامات حمولة Meterpreter", "S0002",
  {"a": g("met~srv.dll", "met~srv.x64.dll", "ext_server_std~api"), "b": g("reflective~loader", "core_channel_~open", "std~api_")}, unsigned=True)
R("SOUR.Miner.Generic", 80, "any", "Cryptocurrency miner configuration", "إعدادات برنامج تعدين عملات رقمية", "T1496",
  {"st": g("stra~tum+tcp://", "stra~tum+ssl://"), "x": g("xm~rig"), "cn": g("crypto~night", "random~x"), "dl": g("donate-le~vel"),
   "pool": g("pool.mine~xmr", "nano~pool.org", "support~xmr.com", "monero~ocean")}, min=2, unsigned=True)
R("SOUR.Spy.Keylogger", 60, "pe", "Keystroke-logging capability", "قدرة على تسجيل ضربات المفاتيح", "T1056.001",
  {"k1": g("[enter]"), "k2": g("[backspace]", "[back]"), "k3": g("[capslock]", "[caps lock]"), "k4": g("[tab]")}, min=3, unsigned=True,
  imports=["GetAsync~KeyState", "SetWindows~HookEx"])
R("SOUR.Stealer.Generic", 80, "any", "Targets saved browser passwords, wallets or messenger sessions", "يستهدف كلمات مرور المتصفحات والمحافظ وجلسات المراسلة", "T1555.003",
  {"chrome": g("\\google\\chrome\\user data"), "login": g("login data"), "ff": g("\\mozilla\\firefox\\profiles", "logins.json"),
   "wal": g("wallet.dat", "\\exodus\\", "\\electrum\\wallets"), "tg": g("telegram desktop\\tdata"), "dc": g("discord\\local storage\\leveldb", "discordcanary")}, min=3, unsigned=True)
R("SOUR.RAT.Family", 85, "any", "Name of a known remote-access trojan family", "اسم عائلة معروفة من أحصنة التحكم عن بعد", "T1219",
  {"a": g("Async~RAT", "Quasar~RAT", "Quasar.Cli~ent", "Dc~Rat", "nj~RAT", "Nano~Core Client", "XWo~rm V", "Venom~RAT", "Breaking-Secu~rity.Net", cs=True)}, unsigned=True)
R("SOUR.Inject.Hollowing", 35, "pe", "Process-hollowing API set", "مجموعة دوال تفريغ العمليات (Process Hollowing)", "T1055.012",
  unsigned=True, imports=["NtUnmap~ViewOfSection", "Write~ProcessMemory", "SetThread~Context", "Resume~Thread"])
R("SOUR.Inject.RemoteThread", 30, "pe", "Classic remote-thread code injection API set", "مجموعة دوال حقن الشيفرة في عملية أخرى", "T1055.002",
  unsigned=True, imports=["Virtual~AllocEx", "Write~ProcessMemory", "CreateRemote~Thread"])
R("SOUR.Evasion.AntiVm", 50, "any", "Checks for virtual machines, sandboxes or analysis tools", "يتحقق من الأجهزة الوهمية وأدوات التحليل", "T1497",
  {"vbox": g("vbox~service", "vbox~guest", "vbox~hook"), "vmw": g("vm~toolsd", "vmware~user", "vmware tools"), "sb": g("sbie~dll.dll"),
   "dbg": g("olly~dbg", "x64~dbg", "process~hacker"), "ws": g("wire~shark", "fiddler", "proc~mon")}, min=3, unsigned=True)
R("SOUR.UAC.Bypass", 80, "any", "Known UAC-bypass registry hijack", "اختطاف سجل معروف لتجاوز UAC", "T1548.002",
  {"reg": g("ms-settings\\shell\\open\\com~mand", "mscfile\\shell\\open\\com~mand"), "bin": g("fod~helper", "event~vwr", "computer~defaults", "sd~clt")}, unsigned=True)
R("SOUR.Exfil.TelegramBot", 60, "any", "Sends data through a Telegram bot", "يرسل بيانات عبر بوت تيليغرام", "T1567",
  {"a": g("api.tele~gram.org/bot"), "b": g("send~document", "send~message")}, unsigned=True)
R("SOUR.Exfil.DiscordWebhook", 55, "any", "Sends data to a Discord webhook", "يرسل بيانات إلى Webhook على ديسكورد", "T1567",
  {"a": g("discord.com/api/web~hooks", "discordapp.com/api/web~hooks")}, unsigned=True)
R("SOUR.Webshell.PHP", 90, "any", "PHP web shell", "صدفة ويب PHP", "T1505.003",
  {"a": g("ev~al($_po~st", "ev~al($_ge~t", "ev~al($_requ~est", "ass~ert($_po~st", "ev~al(base64_de~code(", "sys~tem($_ge~t", "sys~tem($_po~st", "pass~thru($_", "shell_ex~ec($_", wide=False)},
  ext=[".php", ".phtml", ".php3", ".php5", ".inc"])
R("SOUR.Webshell.ASP", 85, "any", "ASP/ASPX web shell", "صدفة ويب ASP", "T1505.003",
  {"e": g("ev~al(requ~est", "exec~ute(requ~est", "ev~al (requ~est", wide=False)}, ext=[".asp", ".aspx", ".ashx", ".asa"])
R("SOUR.Webshell.ASPCmd", 75, "any", "ASPX page that runs commands from the request", "صفحة ASPX تنفّذ أوامر قادمة من الطلب", "T1505.003",
  {"cmd": g("cmd.exe", wide=False), "req": g("request.query~string", "request.form", "request[", wide=False), "run": g("process.start", "process~startinfo", wide=False)},
  ext=[".asp", ".aspx", ".ashx"])
R("SOUR.HackTool.Offensive", 70, "any", "Offensive security tool name", "اسم أداة هجومية معروفة", "T1588.002",
  {"a": g("Rub~eus", "Sharp~Hound", "Seat~belt.Commands", "LaZa~gne", "Safety~Katz", "Power~Sploit", "Invoke-Kerbe~roast", "Invoke-Reflective~PEInjection",
          "Invoke-Shell~code", "Invoke-Token~Manipulation", cs=True)}, unsigned=True)
R("SOUR.USB.Autorun", 60, "any", "autorun.inf that launches a program", "ملف autorun.inf يشغّل برنامجاً تلقائياً", "T1091",
  {"a": g("[auto~run]"), "b": g("open=", "shell~execute=", "shell\\open\\command=")}, ext=[".inf"], max_kb=64)
R("SOUR.LNK.Suspicious", 65, "lnk", "Shortcut that runs a script interpreter with download/hidden arguments", "اختصار يشغّل مفسّر أوامر مع وسائط تنزيل أو إخفاء", "T1204.002",
  {"bin": g("power~shell", "cmd.exe /c", "cmd /c", "ms~hta", "wscript", "cscript", "run~dll32", "regsvr~32", "cert~util", "bits~admin"),
   "arg": g("http://", "https://", " -en~c", "-w hid~den", "-window~style hid~den", "frombase~64string", "%temp%", "%appdata%", "down~loadstr~ing")})
R("SOUR.Script.HiddenBypass", 45, "script", "Runs PowerShell hidden with the execution policy bypassed", "تشغيل PowerShell مخفياً مع تجاوز سياسة التنفيذ", "T1059.001",
  {"a": g("-window~style hid~den", "-w hid~den", "-win hid~den"), "b": g("-execution~policy by~pass", "-ep by~pass", "-exec by~pass")})
R("SOUR.Persist.SchTask", 45, "script", "Creates a scheduled task for persistence", "إنشاء مهمة مجدولة للبقاء في النظام", "T1053.005",
  {"a": g("sch~tasks /create", "sch~tasks.exe /create"), "b": g("/sc onlogon", "/sc minute", "/ru system", "/rl highest", "/sc onstart")})
R("SOUR.JS.Dropper", 70, "script", "JScript downloader/dropper", "سكربت JScript ينزّل ملفاً ويشغّله", "T1059.007",
  {"a": g("active~xobject"), "b": g("wscript.sh~ell", "shell.appli~cation"), "c": g("msxml2.xml~http", "adodb.str~eam", "winhttp.winhttp~request")}, ext=[".js", ".jse", ".wsf", ".hta"])
R("SOUR.Wiper.RawDisk", 30, "pe", "Writes directly to the physical disk", "يكتب مباشرة على القرص الفيزيائي", "T1561",
  {"a": g("\\\\.\\physical~drive")}, unsigned=True, imports=["DeviceIo~Control", "Write~File"])

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "Sour", "Data", "rules.json")
os.makedirs(os.path.dirname(out), exist_ok=True)
json.dump(rules, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(len(rules), "rules ->", os.path.normpath(out))
