/*
    YARA-EDR Advanced Linux Threat Detection Rules

    Sources:
    - Neo23x0/signature-base
    - Elastic Security Labs
    - Trend Micro Research
    - Airbnb BinaryAlert
    - Community contributions

    Categories:
    - BPFDoor/eBPF backdoors
    - Linux rootkits (Umbreon, Orbit)
    - RATs (TinyShell, Pupy)
    - DDoS botnets (XorDDoS variants)
    - Linux ransomware
    - Advanced implants
*/

import "elf"

// =============================================================================
// BPFDoor Backdoor Detection
// =============================================================================

rule Linux_Backdoor_BPFDoor_Generic {
    meta:
        description = "Detects BPFDoor Linux backdoor variants"
        author = "YARA-EDR"
        severity = "critical"
        category = "backdoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"

    strings:
        $s1 = "/var/run/initd.lock" ascii
        $s2 = "[-] Execute command failed" ascii
        $s3 = "hald-addon-acpi: listening on acpi kernel interface" ascii
        $s4 = "/sbin/mingetty /dev" ascii
        $s5 = "pickup -l -t fifo -u" ascii
        $s6 = "HISTFILE=/dev/null" ascii
        $s7 = "export MYSQL_HISTFILE=" ascii
        $s8 = "getshell" ascii
        $s9 = "udpcmd" ascii

        // BPF filter related
        $bpf1 = "BPF_LD" ascii
        $bpf2 = "setsockopt" ascii
        $bpf3 = "SO_ATTACH_FILTER" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1MB and
        (3 of ($s*) or (2 of ($s*) and 2 of ($bpf*)))
}

rule Linux_Backdoor_BPFDoor_Controller {
    meta:
        description = "Detects BPFDoor controller/implant"
        author = "YARA-EDR (based on Florian Roth)"
        severity = "critical"
        category = "backdoor"

    strings:
        $s1 = "[-] Connect failed." ascii
        $s2 = "export MYSQL_HISTFILE=" ascii
        $s3 = "/var/run/haldrund.pid" ascii
        $s4 = "getpasswd" ascii
        $s5 = "magicpacket" ascii

        // TLS cipher strings
        $tls1 = "TLS-CHACHA20-POLY1305-SHA256" ascii
        $tls2 = "TLS_AES_256_GCM_SHA384" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 500KB and
        (3 of ($s*) or (1 of ($tls*) and 2 of ($s*)))
}

// =============================================================================
// Umbreon Rootkit Detection
// =============================================================================

rule Linux_Rootkit_Umbreon {
    meta:
        description = "Detects Umbreon Linux rootkit"
        author = "YARA-EDR (based on Trend Micro)"
        severity = "critical"
        category = "rootkit"
        reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems/"

    strings:
        $s1 = "unfuck_linkmap" ascii
        $s2 = "unhide.rb" ascii
        $s3 = "rkit" ascii fullword
        $s4 = "/etc/ld.so.preload" ascii
        $s5 = "LD_PRELOAD" ascii
        $s6 = "fputs_unlocked" ascii

    condition:
        uint32(0) == 0x464c457f and
        elf.type == elf.ET_DYN and
        filesize < 500KB and
        3 of them
}

rule Linux_Rootkit_Umbreon_Espeon {
    meta:
        description = "Detects Umbreon Espeon backdoor component"
        author = "YARA-EDR (based on Trend Micro)"
        severity = "critical"
        category = "backdoor"

    strings:
        $s1 = "/bin/espeon-shell" ascii
        $s2 = "Usage:" ascii
        $s3 = "-i <interface>" ascii
        $s4 = "listen" ascii

    condition:
        uint32(0) == 0x464c457f and
        elf.type == elf.ET_EXEC and
        filesize < 200KB and
        all of them
}

// =============================================================================
// TinyShell Backdoor Detection
// =============================================================================

rule Linux_Backdoor_TinyShell {
    meta:
        description = "Detects TinyShell Linux backdoor"
        author = "YARA-EDR (based on MalwareMustDie)"
        severity = "high"
        category = "backdoor"

    strings:
        $arg1 = "s:p:" ascii
        $arg2 = "[ -s secret ]" ascii
        $arg3 = "Usage: %s" ascii

        $func1 = "socket" ascii
        $func2 = "connect" ascii
        $func3 = "dup2" ascii
        $func4 = "execl" ascii
        $func5 = "setsid" ascii
        $func6 = "ttyname" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 100KB and
        (2 of ($arg*) and 4 of ($func*))
}

rule Linux_Backdoor_TinyShell_Backconnect {
    meta:
        description = "Detects TinyShell backconnect variant"
        author = "YARA-EDR"
        severity = "high"
        category = "backdoor"

    strings:
        $s1 = "backconnect" ascii nocase
        $s2 = "getenv" ascii
        $s3 = "TERM=" ascii
        $s4 = "/bin/sh" ascii
        $s5 = "-c" ascii fullword

        $net1 = "inet_addr" ascii
        $net2 = "htons" ascii
        $net3 = "AF_INET" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 100KB and
        (3 of ($s*) and 2 of ($net*))
}

// =============================================================================
// XorDDoS Detection
// =============================================================================

rule Linux_Trojan_XorDDoS {
    meta:
        description = "Detects XOR.DDoS Linux trojan"
        author = "YARA-EDR (based on Akamai CSIRT)"
        severity = "high"
        category = "trojan"

    strings:
        $s1 = "BB2FA36AAA9541F0" ascii
        $s2 = "md5=" ascii
        $s3 = "denyip=" ascii
        $s4 = "filename=" ascii
        $s5 = "rmfile=" ascii
        $s6 = "exec_packet" ascii
        $s7 = "build_iphdr" ascii

    condition:
        uint32(0) == 0x464c457f and
        4 of them
}

rule Linux_Trojan_XorDDoS_Variant {
    meta:
        description = "Detects XOR.DDoS variant with encryption"
        author = "YARA-EDR"
        severity = "high"
        category = "trojan"

    strings:
        $xor1 = { 31 ?? 83 ?? 01 3? ?? 7? } // XOR decryption loop pattern
        $xor2 = "decrypt" ascii nocase

        $cfg1 = "g_maession" ascii
        $cfg2 = "g_cpession" ascii
        $cfg3 = "socket_pr" ascii

        $cmd1 = "stopattk" ascii
        $cmd2 = "getlocalip" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 2MB and
        (1 of ($xor*) and 2 of ($cfg*)) or
        (3 of ($cfg*) or (1 of ($cmd*) and 1 of ($cfg*)))
}

// =============================================================================
// Pupy RAT Detection
// =============================================================================

rule Linux_RAT_Pupy {
    meta:
        description = "Detects Pupy RAT Linux variant"
        author = "YARA-EDR (based on Florian Roth)"
        severity = "high"
        category = "rat"
        reference = "https://github.com/n1nj4sec/pupy"

    strings:
        $s1 = "reflectively inject a dll into a process" ascii nocase
        $s2 = "ld_preload_inject_dll" ascii
        $s3 = "linux_inject_dll" ascii
        $s4 = "PUPY_CONFIG_COMES_HERE" ascii
        $s5 = "pupyutils.dns" ascii
        $s6 = "pupwinutils" ascii
        $s7 = "the keylogger is already started" ascii nocase
        $s8 = "dumping lsa secrets" ascii nocase
        $s9 = "pupyimporter" ascii
        $s10 = "pupy_" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 7MB and
        3 of them
}

// =============================================================================
// Orbit/eBPF Malware Detection
// =============================================================================

rule Linux_Malware_Orbit {
    meta:
        description = "Detects Orbit Linux malware with eBPF capabilities"
        author = "YARA-EDR"
        severity = "critical"
        category = "malware"
        reference = "https://www.intezer.com/blog/research/orbit-new-undetected-linux-threat/"

    strings:
        $s1 = "/dev/shm" ascii
        $s2 = "LD_PRELOAD" ascii
        $s3 = "/etc/ld.so.preload" ascii
        $s4 = "libOrbit" ascii nocase
        $s5 = "orbit.so" ascii nocase

        // Hook functions
        $hook1 = "readdir" ascii
        $hook2 = "readdir64" ascii
        $hook3 = "fopen" ascii
        $hook4 = "fopen64" ascii
        $hook5 = "open" ascii fullword
        $hook6 = "stat" ascii fullword
        $hook7 = "lstat" ascii fullword

        // SSH stealing
        $ssh1 = "ssh" ascii
        $ssh2 = "pam_" ascii
        $ssh3 = "password" ascii nocase

    condition:
        uint32(0) == 0x464c457f and
        elf.type == elf.ET_DYN and
        filesize < 1MB and
        (2 of ($s*) and 4 of ($hook*)) or
        (3 of ($s*) and 2 of ($ssh*))
}

rule Linux_Rootkit_eBPF_Generic {
    meta:
        description = "Detects generic eBPF-based rootkit indicators"
        author = "YARA-EDR"
        severity = "high"
        category = "rootkit"

    strings:
        $ebpf1 = "bpf_probe" ascii
        $ebpf2 = "bpf_kprobe" ascii
        $ebpf3 = "bpf_tracepoint" ascii
        $ebpf4 = "BPF_PROG_TYPE" ascii
        $ebpf5 = "bpf_map_" ascii
        $ebpf6 = "SEC(\"kprobe" ascii
        $ebpf7 = "bpf_override_return" ascii

        // Hiding indicators
        $hide1 = "hide_pid" ascii
        $hide2 = "hide_file" ascii
        $hide3 = "hide_port" ascii
        $hide4 = "rootkit" ascii nocase

    condition:
        uint32(0) == 0x464c457f and
        filesize < 2MB and
        (3 of ($ebpf*) and 1 of ($hide*))
}

// =============================================================================
// Symbiote Malware Detection
// =============================================================================

rule Linux_Malware_Symbiote {
    meta:
        description = "Detects Symbiote Linux malware"
        author = "YARA-EDR"
        severity = "critical"
        category = "malware"
        reference = "https://blogs.blackberry.com/en/2022/06/symbiote-a-new-nearly-impossible-to-detect-linux-threat"

    strings:
        $s1 = "LD_PRELOAD" ascii
        $s2 = "/etc/ld.so.preload" ascii

        // Network hiding
        $net1 = "/proc/net/tcp" ascii
        $net2 = "/proc/net/tcp6" ascii
        $net3 = "/proc/net/udp" ascii

        // Process hiding
        $proc1 = "/proc/" ascii
        $proc2 = "cmdline" ascii
        $proc3 = "comm" ascii

        // BPF hooks
        $bpf1 = "BPF_" ascii
        $bpf2 = "libpcap" ascii

        // Credential stealing
        $cred1 = "pam_sm_" ascii
        $cred2 = "pam_authenticate" ascii

    condition:
        uint32(0) == 0x464c457f and
        elf.type == elf.ET_DYN and
        filesize < 2MB and
        (all of ($s*) and 2 of ($net*)) or
        (all of ($s*) and 2 of ($proc*) and 1 of ($cred*)) or
        (all of ($s*) and 1 of ($bpf*) and 1 of ($cred*))
}

// =============================================================================
// Linux Ransomware Detection
// =============================================================================

rule Linux_Ransomware_Advanced {
    meta:
        description = "Detects generic Linux ransomware indicators"
        author = "YARA-EDR"
        severity = "critical"
        category = "ransomware"

    strings:
        // Common ransom note patterns
        $note1 = "Your files have been encrypted" ascii nocase
        $note2 = "bitcoin" ascii nocase
        $note3 = "decrypt" ascii nocase
        $note4 = "ransom" ascii nocase
        $note5 = ".onion" ascii
        $note6 = "README" ascii
        $note7 = "RECOVER" ascii nocase

        // Encryption indicators
        $enc1 = "openssl" ascii
        $enc2 = "AES" ascii
        $enc3 = "RSA" ascii
        $enc4 = "encrypt" ascii nocase
        $enc5 = "EVP_" ascii

        // File operations
        $file1 = "readdir" ascii
        $file2 = "rename" ascii
        $file3 = ".locked" ascii
        $file4 = ".encrypted" ascii
        $file5 = ".enc" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 10MB and
        (2 of ($note*) and 2 of ($enc*)) or
        (1 of ($note*) and 2 of ($enc*) and 2 of ($file*))
}

rule Linux_Ransomware_RansomEXX {
    meta:
        description = "Detects RansomEXX Linux ransomware"
        author = "YARA-EDR"
        severity = "critical"
        category = "ransomware"
        reference = "https://www.trendmicro.com/en_us/research/20/k/analysis-of-ransomexx-a-closer-look-at-its-activities.html"

    strings:
        $s1 = "!NEWS FOR" ascii
        $s2 = ".README" ascii
        $s3 = "mbedtls" ascii
        $s4 = "pthread_create" ascii
        $s5 = "fstatat64" ascii

        // Encryption patterns
        $enc1 = "AES-256" ascii
        $enc2 = "RSA-4096" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (3 of ($s*) and 1 of ($enc*))
}

rule Linux_Ransomware_HelloKitty {
    meta:
        description = "Detects HelloKitty Linux ransomware"
        author = "YARA-EDR"
        severity = "critical"
        category = "ransomware"

    strings:
        $s1 = "esxcli" ascii
        $s2 = "vim-cmd" ascii
        $s3 = "VMkernel" ascii nocase
        $s4 = "vmsvc" ascii
        $s5 = ".vmdk" ascii
        $s6 = ".vmx" ascii

        // Ransom indicators
        $ransom1 = "Hello Kitty" ascii nocase
        $ransom2 = "Your files are encrypted" ascii nocase

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (3 of ($s*) or 1 of ($ransom*))
}

rule Linux_Ransomware_Hive {
    meta:
        description = "Detects Hive Linux ransomware"
        author = "YARA-EDR"
        severity = "critical"
        category = "ransomware"

    strings:
        $s1 = ".hive" ascii
        $s2 = "HOW_TO_DECRYPT" ascii
        $s3 = "esxcli" ascii
        $s4 = "vmfs" ascii
        $s5 = "nbd" ascii

        // Go-specific
        $go1 = "main.main" ascii
        $go2 = "runtime.main" ascii
        $go3 = "Go build" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 10MB and
        (3 of ($s*) or (2 of ($s*) and 2 of ($go*)))
}

// =============================================================================
// Additional Linux Implants
// =============================================================================

rule Linux_Backdoor_Tsunami {
    meta:
        description = "Detects Tsunami/Kaiten IRC botnet"
        author = "YARA-EDR"
        severity = "high"
        category = "botnet"

    strings:
        $s1 = "PRIVMSG" ascii
        $s2 = "NOTICE" ascii
        $s3 = "NICK" ascii
        $s4 = "JOIN" ascii
        $s5 = "PING" ascii
        $s6 = "PONG" ascii

        $cmd1 = "TSUNAMI" ascii nocase
        $cmd2 = "KAITEN" ascii nocase
        $cmd3 = "!udp" ascii
        $cmd4 = "!syn" ascii
        $cmd5 = "!get" ascii
        $cmd6 = "!sh" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 500KB and
        (4 of ($s*) and 2 of ($cmd*))
}

rule Linux_Backdoor_Rekoobe {
    meta:
        description = "Detects Rekoobe/Tiny SHell variant backdoor"
        author = "YARA-EDR"
        severity = "high"
        category = "backdoor"

    strings:
        $s1 = "/dev/pts" ascii
        $s2 = "/bin/sh" ascii
        $s3 = "socket" ascii
        $s4 = "connect" ascii
        $s5 = "fork" ascii
        $s6 = "dup2" ascii

        // Magic bytes
        $magic = { 7F 45 4C 46 }

        // Config patterns
        $cfg1 = "HISTFILE" ascii
        $cfg2 = "unset" ascii
        $cfg3 = "TERM" ascii

    condition:
        $magic at 0 and
        filesize < 100KB and
        (4 of ($s*) and 2 of ($cfg*))
}

rule Linux_Miner_Generic_Dropper {
    meta:
        description = "Detects generic Linux cryptominer dropper scripts"
        author = "YARA-EDR"
        severity = "medium"
        category = "cryptominer"

    strings:
        $s1 = "curl" ascii
        $s2 = "wget" ascii
        $s3 = "chmod +x" ascii
        $s4 = "/tmp/" ascii
        $s5 = "nohup" ascii
        $s6 = "crontab" ascii

        $miner1 = "xmrig" ascii nocase
        $miner2 = "minerd" ascii nocase
        $miner3 = "stratum" ascii
        $miner4 = "pool" ascii
        $miner5 = "cryptonight" ascii nocase

        $kill1 = "pkill" ascii
        $kill2 = "killall" ascii
        $kill3 = "kill -9" ascii

    condition:
        filesize < 500KB and
        (3 of ($s*) and 2 of ($miner*)) or
        (3 of ($s*) and 1 of ($miner*) and 1 of ($kill*))
}

rule Linux_Backdoor_ChaosRAT {
    meta:
        description = "Detects CHAOS RAT Linux variant"
        author = "YARA-EDR"
        severity = "high"
        category = "rat"

    strings:
        $s1 = "chaos" ascii nocase
        $s2 = "screenshot" ascii
        $s3 = "download" ascii
        $s4 = "upload" ascii
        $s5 = "execute" ascii
        $s6 = "shell" ascii

        // Go indicators
        $go1 = "main.main" ascii
        $go2 = "runtime." ascii

        // Network
        $net1 = "websocket" ascii nocase
        $net2 = "http" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 15MB and
        (4 of ($s*) and 1 of ($go*) and 1 of ($net*))
}

rule Linux_Backdoor_GTPDOOR {
    meta:
        description = "Detects GTPDOOR telecom backdoor"
        author = "YARA-EDR"
        severity = "critical"
        category = "backdoor"
        reference = "https://doubleagent.net/telecommunications/backdoor/gtp/2024/02/27/GTPDOOR-COVERT-TELCO-BACKDOOR"

    strings:
        $s1 = "GTP-C" ascii
        $s2 = "GTP-U" ascii
        $s3 = "gtpv1" ascii nocase
        $s4 = "gtpv2" ascii nocase
        $s5 = "2152" ascii // GTP-U port
        $s6 = "2123" ascii // GTP-C port

        // Backdoor commands
        $cmd1 = "execve" ascii
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "socket" ascii
        $cmd4 = "RAW" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 2MB and
        (3 of ($s*) and 2 of ($cmd*))
}

rule Linux_Trojan_Plague {
    meta:
        description = "Detects Plague backdoor related to PAM auth tampering"
        author = "YARA-EDR"
        severity = "critical"
        category = "backdoor"

    strings:
        $s1 = "pam_sm_authenticate" ascii
        $s2 = "pam_sm_setcred" ascii
        $s3 = "pam_sm_acct_mgmt" ascii
        $s4 = "/lib/security" ascii
        $s5 = "/etc/pam.d" ascii

        // Backdoor strings
        $bd1 = "master_pass" ascii nocase
        $bd2 = "backdoor" ascii nocase
        $bd3 = "magic" ascii

    condition:
        uint32(0) == 0x464c457f and
        elf.type == elf.ET_DYN and
        filesize < 500KB and
        (3 of ($s*) and 1 of ($bd*))
}
