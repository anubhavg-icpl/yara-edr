/*
    Linux APT (Advanced Persistent Threat) Rules
    Detection signatures for state-sponsored and sophisticated Linux malware
    Author: YARA-EDR
*/

import "elf"

// ============================================================================
// APT28 / Fancy Bear
// ============================================================================

rule Linux_APT28_Drovorub_Agent {
    meta:
        description = "Detects APT28 Drovorub Linux implant agent"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT28"
        reference = "NSA/FBI Joint Advisory"
    strings:
        $s1 = "module_hidden" ascii
        $s2 = "module_show" ascii
        $s3 = "hide_pid" ascii
        $s4 = "unhide_pid" ascii
        $s5 = "/proc/net/packet" ascii
        $s6 = "do_fork" ascii
        $json1 = "\"clientid\"" ascii
        $json2 = "\"token\"" ascii
        $json3 = "\"session\"" ascii
        $kernel1 = "kallsyms_lookup_name" ascii
        $kernel2 = "register_kprobe" ascii
    condition:
        uint32(0) == 0x464c457f and (4 of ($s*) or (2 of ($json*) and any of ($kernel*)))
}

rule Linux_APT28_Drovorub_Kernel {
    meta:
        description = "Detects APT28 Drovorub kernel module rootkit"
        author = "YARA-EDR"
        severity = "critical"
        category = "rootkit"
        apt_group = "APT28"
    strings:
        $s1 = "rootkit" ascii
        $s2 = "KBUILD_MODNAME" ascii
        $s3 = "sys_call_table" ascii
        $s4 = "__x64_sys" ascii
        $s5 = "hide_module" ascii
        $s6 = "orig_getdents" ascii
        $s7 = "orig_getdents64" ascii
        $hook1 = "ftrace_set_filter_ip" ascii
        $hook2 = "register_ftrace_function" ascii
    condition:
        uint32(0) == 0x464c457f and (4 of ($s*) or all of ($hook*))
}

rule Linux_APT28_XAgent {
    meta:
        description = "Detects APT28 XAgent/Sofacy Linux variant"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT28"
    strings:
        $s1 = "XTunnel" ascii
        $s2 = "XTUNNELX" ascii
        $s3 = "Sofacy" ascii nocase
        $s4 = "/tmp/.sync." ascii
        $c2_1 = "POST /index.php" ascii
        $c2_2 = "GET /search?" ascii
        $enc1 = { 31 ?? 89 ?? 31 ?? 83 ?? ?? 89 }
        $rc4 = { 0F B6 ?? 03 ?? 0F B6 ?? 8A ?? ?? 88 }
    condition:
        uint32(0) == 0x464c457f and (2 of ($s*) or any of ($c2*) or all of ($enc*, $rc4))
}

// ============================================================================
// APT29 / Cozy Bear
// ============================================================================

rule Linux_APT29_WellMess {
    meta:
        description = "Detects APT29 WellMess malware for Linux"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT29"
    strings:
        $go1 = "main.wellMess" ascii
        $go2 = "main.encrypt" ascii
        $go3 = "main.decrypt" ascii
        $s1 = "wellmess" ascii nocase
        $s2 = "script<" ascii
        $s3 = ">script" ascii
        $http = "Mozilla/5.0" ascii
        $ua = "User-Agent:" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($go*) or (2 of ($s*) and $http and $ua))
}

rule Linux_APT29_WellMail {
    meta:
        description = "Detects APT29 WellMail malware for Linux"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT29"
    strings:
        $go1 = "main.wellMail" ascii
        $go2 = "main.sendMail" ascii
        $go3 = "main.recvMail" ascii
        $s1 = "Content-Type: multipart" ascii
        $s2 = "MIME-Version:" ascii
        $cert = "-----BEGIN CERTIFICATE-----" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($go*) or (all of ($s*) and $cert))
}

rule Linux_APT29_MiniDuke {
    meta:
        description = "Detects APT29 MiniDuke Linux variant"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT29"
    strings:
        $s1 = "twitter.com" ascii
        $s2 = "github.com" ascii
        $s3 = "jpeg" ascii
        $s4 = ".gif" ascii
        $enc = { 8B ?? 83 ?? ?? 33 ?? 89 ?? 83 ?? ?? }
        $dec = { 0F B6 ?? 33 ?? 88 ?? 41 }
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) and any of ($enc, $dec))
}

// ============================================================================
// Lazarus Group / APT38
// ============================================================================

rule Linux_Lazarus_DreamJob {
    meta:
        description = "Detects Lazarus DreamJob campaign Linux malware"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "Lazarus"
    strings:
        $s1 = "curl_easy_init" ascii
        $s2 = "curl_easy_perform" ascii
        $s3 = "/tmp/.ICE-unix/" ascii
        $s4 = "Dream Job" ascii nocase
        $s5 = "LinkedIn" ascii
        $chrome = "Chrome/9" ascii
        $ua = "Mozilla/5.0" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or (all of ($chrome, $ua) and any of ($s*)))
}

rule Linux_Lazarus_Dacls_RAT {
    meta:
        description = "Detects Lazarus Dacls RAT for Linux"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "Lazarus"
    strings:
        $s1 = "c_2910.cls" ascii
        $s2 = "k_3872.cls" ascii
        $s3 = "ata:image/" ascii
        $s4 = "/tmp/.sess_" ascii
        // removed unused cmd1
        // removed cmd2
        $plugin = "plugin_file" ascii
        $plugin2 = "plugin_process" ascii
        $plugin3 = "plugin_reverse_p2p" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or 2 of ($plugin*))
}

rule Linux_Lazarus_AppleJeus {
    meta:
        description = "Detects Lazarus AppleJeus cryptocurrency targeting malware"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "Lazarus"
    strings:
        $s1 = "getenv" ascii
        $s2 = "HOSTNAME" ascii
        $s3 = "uname" ascii
        $crypto1 = "bitcoin" ascii nocase
        $crypto2 = "ethereum" ascii nocase
        $crypto3 = "wallet" ascii nocase
        $exchange = "celas" ascii nocase
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) and 2 of ($crypto*)) or $exchange
}

// ============================================================================
// Chinese APT Groups
// ============================================================================

rule Linux_APT41_MessageTap {
    meta:
        description = "Detects APT41 MessageTap SMS interception malware"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT41"
    strings:
        $s1 = "keyword_parm.txt" ascii
        $s2 = "imsi_parm.txt" ascii
        $s3 = "phone_parm.txt" ascii
        $s4 = "cdr_spool" ascii
        $s5 = "IMSI" ascii
        $s6 = "SMSC" ascii
        $smpp = "SMPP" ascii
        $func1 = "libpcap" ascii
        $func2 = "pcap_open" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or ($smpp and all of ($func*)))
}

rule Linux_APT41_Speculoos {
    meta:
        description = "Detects APT41 Speculoos backdoor"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT41"
    strings:
        $s1 = "Speculoos" ascii
        $s2 = "/tmp/.X11-unix/" ascii
        $s3 = "OpenSSL" ascii
        $cmd1 = "cmd_download" ascii
        $cmd2 = "cmd_upload" ascii
        $cmd3 = "cmd_shell" ascii
        $xor = { 80 ?? ?? ?? 00 00 00 31 }
    condition:
        uint32(0) == 0x464c457f and (2 of ($s*) or 2 of ($cmd*) or $xor)
}

rule Linux_APT10_Quasar {
    meta:
        description = "Detects APT10 QuasarRAT Linux variant"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT10"
    strings:
        $s1 = "QuasarClient" ascii
        $s2 = "GetSystemInfo" ascii
        $s3 = "BSOD" ascii
        $s4 = "FileManager" ascii
        $cmd = "DoShellExecute" ascii
        $keylog = "KeyLogger" ascii
        $pass = "PasswordRecovery" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of them)
}

rule Linux_APT10_SodaMaster {
    meta:
        description = "Detects APT10 SodaMaster backdoor"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT10"
    strings:
        $s1 = "SodaMaster" ascii nocase
        $s2 = "stackpivot" ascii
        $s3 = "shellcode" ascii
        $s4 = "/proc/self/maps" ascii
        $s5 = "mprotect" ascii
        $config = { 48 8D ?? ?? ?? ?? ?? 48 89 ?? 48 8D }
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or $config)
}

// ============================================================================
// Russian APT Groups (Additional)
// ============================================================================

rule Linux_Turla_Penguin {
    meta:
        description = "Detects Turla Penguin/Penquin Linux implant"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "Turla"
    strings:
        $s1 = "PENGUIN" ascii
        $s2 = "pfinet" ascii
        $s3 = "/dev/shm/" ascii
        $s4 = ".syslog" ascii
        $net1 = "socket" ascii
        $net2 = "connect" ascii
        $net3 = "recvfrom" ascii
        $crypt = { 31 C0 8A ?? 32 ?? 88 ?? 40 3D }
    condition:
        uint32(0) == 0x464c457f and (2 of ($s*) and 2 of ($net*)) or $crypt
}

rule Linux_Turla_Carbon {
    meta:
        description = "Detects Turla Carbon framework Linux component"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "Turla"
    strings:
        $s1 = "Carbon" ascii
        $s2 = "task_filepath" ascii
        $s3 = "config_filepath" ascii
        $s4 = "check_timeout" ascii
        $s5 = "inject_method" ascii
        $pipe = "mkfifo" ascii
        $enc = "base64" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or (all of ($pipe, $enc) and any of ($s*)))
}

rule Linux_Sandworm_VPNFilter {
    meta:
        description = "Detects Sandworm VPNFilter malware (stage 2/3)"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "Sandworm"
    strings:
        $s1 = "/var/run/vpnfilterw" ascii
        $s2 = "/var/run/tor" ascii
        $s3 = "api.ipify.org" ascii
        $s4 = "toknowall" ascii
        $s5 = "photobucket" ascii
        $s6 = "SOCKS5" ascii
        $modbus = "modbus" ascii
        $scada = "SCADA" ascii nocase
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or any of ($modbus, $scada))
}

rule Linux_Sandworm_Cyclops_Blink {
    meta:
        description = "Detects Sandworm Cyclops Blink malware"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "Sandworm"
    strings:
        $s1 = "core_module" ascii
        $s2 = "file_download" ascii
        $s3 = "file_upload" ascii
        $s4 = "device_info" ascii
        $s5 = "/lib/firmware/updates" ascii
        $firm = "firmware" ascii
        $persist = "iptables" ascii
        $openssl = "OpenSSL" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) and any of ($firm, $persist, $openssl))
}

// ============================================================================
// Iranian APT Groups
// ============================================================================

rule Linux_APT33_Elfin {
    meta:
        description = "Detects APT33 Elfin group Linux tools"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT33"
    strings:
        $s1 = "TURNEDUP" ascii
        $s2 = "DROPSHOT" ascii
        $s3 = "STONEDRILL" ascii
        $s4 = "notped" ascii
        $wiper = { 55 48 89 E5 48 83 EC ?? B8 00 00 00 00 }
        $del = "/bin/rm -rf" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($s*) or ($wiper and $del))
}

rule Linux_APT34_OilRig_DNSpionage {
    meta:
        description = "Detects APT34 OilRig DNSpionage implant"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "APT34"
    strings:
        $s1 = "DNSpionage" ascii nocase
        $s2 = "DNSExfil" ascii
        $dns1 = "res_query" ascii
        $dns2 = "res_search" ascii
        $dns3 = "ns_initparse" ascii
        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
        $hex = "0123456789abcdef" ascii
    condition:
        uint32(0) == 0x464c457f and (any of ($s*) or (2 of ($dns*) and any of ($b64, $hex)))
}

rule Linux_MuddyWater {
    meta:
        description = "Detects MuddyWater Linux components"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
        apt_group = "MuddyWater"
    strings:
        $s1 = "powershell" ascii nocase
        $s2 = "LaZagne" ascii nocase
        $s3 = "Invoke-" ascii
        $s4 = "mimikatz" ascii nocase
        $py1 = "import socket" ascii
        $py2 = "subprocess" ascii
        $py3 = "base64" ascii
    condition:
        (2 of ($s*)) or (all of ($py*) and any of ($s*))
}

// ============================================================================
// Emotet / Trickbot / Ransomware Groups
// ============================================================================

rule Linux_Emotet_Loader {
    meta:
        description = "Detects Emotet Linux loader variants"
        author = "YARA-EDR"
        severity = "critical"
        category = "loader"
    strings:
        $s1 = "Emotet" ascii nocase
        $s2 = "Geodo" ascii nocase
        $epoch = "epoch" ascii nocase
        $http1 = "POST /" ascii
        $http2 = "Cookie:" ascii
        $http3 = "Content-Type: application/x-www-form-urlencoded" ascii
        $enc = { 8B ?? 33 ?? 83 ?? ?? 8B ?? 33 ?? }
    condition:
        uint32(0) == 0x464c457f and (any of ($s*, $epoch) or (2 of ($http*) and $enc))
}

rule Linux_Trickbot_Anchor {
    meta:
        description = "Detects TrickBot Anchor Linux variant"
        author = "YARA-EDR"
        severity = "critical"
        category = "trojan"
    strings:
        $s1 = "anchor_dns" ascii
        $s2 = "anchorDNS" ascii
        $s3 = "/tmp/.anchor" ascii
        $s4 = "getSystemInfo" ascii
        // removed unused dns
        // removed curl
        $go = "runtime.gopanic" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($s*) or ($go and any of ($s*)))
}

// ============================================================================
// Generic APT Indicators
// ============================================================================

rule Linux_APT_Generic_Implant {
    meta:
        description = "Generic detection for APT-style Linux implants"
        author = "YARA-EDR"
        severity = "high"
        category = "apt"
    strings:
        $persist1 = "/etc/rc.local" ascii
        $persist2 = "/etc/init.d/" ascii
        $persist3 = "systemctl enable" ascii
        $persist4 = ".service" ascii
        $hide1 = "LD_PRELOAD" ascii
        $hide2 = "/proc/self/fd" ascii
        $hide3 = "unlink" ascii
        $c2_1 = "https://" ascii
        $c2_2 = "POST" ascii
        $c2_3 = "User-Agent" ascii
        $enc1 = "AES" ascii
        $enc2 = "RSA" ascii
        $enc3 = "EVP_Cipher" ascii
        // removed unused cmd1
        // removed cmd2
        $cmd3 = "system" ascii
    condition:
        uint32(0) == 0x464c457f and
        (2 of ($persist*) and 2 of ($hide*)) or
        (all of ($c2*) and any of ($enc*) and any of ($cmd*))
}

rule Linux_APT_Beacon_Activity {
    meta:
        description = "Detects APT beacon/C2 communication patterns"
        author = "YARA-EDR"
        severity = "high"
        category = "apt"
    strings:
        $sleep1 = "sleep" ascii
        $sleep2 = "nanosleep" ascii
        $timer = "setitimer" ascii
        $jitter = "rand" ascii
        $net1 = "socket" ascii
        $net2 = "connect" ascii
        $net3 = "send" ascii
        $net4 = "recv" ascii
        $loop = { EB ?? 83 ?? ?? 7? ?? }
    condition:
        uint32(0) == 0x464c457f and
        (any of ($sleep*, $timer) and $jitter and 3 of ($net*)) or
        ($loop and 2 of ($net*))
}

rule Linux_APT_Data_Exfiltration {
    meta:
        description = "Detects data exfiltration techniques used by APT groups"
        author = "YARA-EDR"
        severity = "high"
        category = "apt"
    strings:
        $arch1 = "tar " ascii
        $arch2 = "gzip" ascii
        $arch3 = "zip" ascii
        $arch4 = ".tar.gz" ascii
        $arch5 = ".zip" ascii
        $enc1 = "openssl enc" ascii
        $enc2 = "gpg" ascii
        $enc3 = "base64" ascii
        $net1 = "curl" ascii
        $net2 = "wget" ascii
        $net3 = "nc " ascii
        $net4 = "scp" ascii
        $net5 = "sftp" ascii
        $cloud1 = "s3://" ascii
        $cloud2 = "dropbox" ascii nocase
        $cloud3 = "drive.google" ascii
    condition:
        (any of ($arch*) and any of ($enc*) and any of ($net*)) or
        (any of ($cloud*) and any of ($arch*))
}
