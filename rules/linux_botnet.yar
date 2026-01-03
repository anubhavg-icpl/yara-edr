/*
    Linux Worm, Botnet, and DDoS Tool Detection Rules
    Detects various Linux botnets, worms, and DDoS attack tools
    Author: YARA-EDR
*/

import "elf"

// ============================================================================
// Mirai Botnet Family
// ============================================================================

rule Linux_Botnet_Mirai {
    meta:
        description = "Detects Mirai botnet and variants"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "MIRAI" ascii
        $s2 = "/bin/busybox" ascii
        $s3 = "LOLNOGTFO" ascii
        $s4 = "TSUNAMI" ascii
        $cmd1 = "scanner" ascii
        $cmd2 = "killer" ascii
        $cmd3 = "attack" ascii
        $flood1 = "UDP" ascii
        $flood2 = "SYN" ascii
        $flood3 = "ACK" ascii
        $flood4 = "GRE" ascii
        // removed xor pattern
        $telnet = "telnet" ascii
        // removed auth
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or (3 of ($cmd*, $flood*) and $telnet))
}

rule Linux_Botnet_Mirai_Variant_Satori {
    meta:
        description = "Detects Satori/Okiru Mirai variant"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "satori" ascii nocase
        $s2 = "okiru" ascii nocase
        $s3 = "masuta" ascii nocase
        $huawei = "Huawei" ascii nocase
        $realtek = "realtek" ascii nocase
        $upnp = "UPnP" ascii
        $soap = "SOAP" ascii
        $tr069 = "TR-069" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or (2 of ($huawei, $realtek, $upnp, $soap, $tr069)))
}

rule Linux_Botnet_Mirai_Variant_Mozi {
    meta:
        description = "Detects Mozi botnet (Mirai variant)"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "Mozi" ascii
        $s2 = "mozi.m" ascii
        $s3 = "mozi.a" ascii
        $dht = "DHT" ascii
        $p2p = "BitTorrent" ascii
        // removed config
        // removed config2
        $iot = "telnet" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or (any of ($dht, $p2p) and $iot))
}

// ============================================================================
// Gafgyt/Bashlite/Qbot Family
// ============================================================================

rule Linux_Botnet_Gafgyt {
    meta:
        description = "Detects Gafgyt/Bashlite/Qbot botnet"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "GAFGYT" ascii nocase
        $s2 = "BASHLITE" ascii nocase
        $s3 = "LIZKEBAB" ascii nocase
        $s4 = "QBOT" ascii nocase
        $s5 = "TORLUS" ascii nocase
        $cmd1 = "PING" ascii
        $cmd2 = "HOLD" ascii
        $cmd3 = "JUNK" ascii
        $cmd4 = "UDP" ascii
        $cmd5 = "TCP" ascii
        $busybox = "busybox" ascii
        $shell = "/bin/sh" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or (3 of ($cmd*) and any of ($busybox, $shell)))
}

// ============================================================================
// Hajime Botnet
// ============================================================================

rule Linux_Botnet_Hajime {
    meta:
        description = "Detects Hajime IoT botnet"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "hajime" ascii nocase
        $s2 = ".i.hajime" ascii
        $s3 = "atk." ascii
        $dht = "DHT" ascii
        $torrent = "BitTorrent" ascii
        $rc4 = "RC4" ascii
        $sign = "ed25519" ascii
        $pubkey = "pubkey" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or (any of ($dht, $torrent) and any of ($rc4, $sign, $pubkey)))
}

// ============================================================================
// XOR.DDoS
// ============================================================================

rule Linux_Botnet_XOR_DDoS {
    meta:
        description = "Detects XOR.DDoS botnet"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "xor.ddos" ascii nocase
        $s2 = "BB2FA36AAA9541F0" ascii
        $s3 = "/lib/udev/udev" ascii
        $s4 = "/boot/pro" ascii
        $xor_key = { BB 2F A3 6A AA 95 41 F0 }
        $persist1 = "/etc/init.d/" ascii
        $persist2 = "/etc/rc" ascii
        $persist3 = "chkconfig" ascii
        $flood = "syn_flood" ascii
        $flood2 = "dns_flood" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or $xor_key or (any of ($persist*) and any of ($flood*)))
}

// ============================================================================
// Kaiten/Tsunami
// ============================================================================

rule Linux_Botnet_Kaiten {
    meta:
        description = "Detects Kaiten/Tsunami IRC botnet"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "KAITEN" ascii
        $s2 = "kaiten" ascii
        $s3 = "TSUNAMI" ascii
        $irc1 = "PRIVMSG" ascii
        $irc2 = "NICK" ascii
        $irc3 = "JOIN #" ascii
        $irc4 = "PING" ascii
        $irc5 = "PONG" ascii
        $cmd1 = "!UDP" ascii
        $cmd2 = "!SYN" ascii
        $cmd3 = "!PAN" ascii
        $cmd4 = "!UNKNOWN" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or (2 of ($irc*) and any of ($cmd*)))
}

// ============================================================================
// BillGates/Elknot
// ============================================================================

rule Linux_Botnet_BillGates {
    meta:
        description = "Detects BillGates/Elknot botnet"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "BillGates" ascii nocase
        $s2 = "elknot" ascii nocase
        $s3 = "Setfilehander" ascii
        $s4 = "Createthread" ascii
        $cmd1 = "ATTACK_DNS" ascii
        $cmd2 = "ATTACK_SYN" ascii
        $cmd3 = "ATTACK_UDP" ascii
        $service = "DbSecuritySpt" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or (2 of ($cmd*) and $service))
}

// ============================================================================
// Linux Worms
// ============================================================================

rule Linux_Worm_Generic {
    meta:
        description = "Detects generic Linux worm behavior"
        author = "YARA-EDR"
        severity = "high"
        category = "worm"
    strings:
        $scan1 = "socket" ascii
        $scan2 = "connect" ascii
        $scan3 = "inet_addr" ascii
        // removed port patterns
        // removed port patterns
        $brute1 = "root" ascii
        $brute2 = "admin" ascii
        $brute3 = "password" ascii
        $spread1 = "scp" ascii
        $spread2 = "wget" ascii
        $spread3 = "curl" ascii
        // removed chmod
    condition:
        uint32(0) == 0x464c457f and
        (all of ($scan*) and any of ($brute*) and any of ($spread*))
}

rule Linux_Worm_SSH_Bruteforce {
    meta:
        description = "Detects SSH brute-force worm"
        author = "YARA-EDR"
        severity = "critical"
        category = "worm"
    strings:
        $ssh1 = "ssh" ascii
        $ssh2 = "libssh" ascii
        $ssh3 = "paramiko" ascii
        $ssh4 = "SSH-2.0" ascii
        $auth1 = "password" ascii
        $auth2 = "keyboard-interactive" ascii
        $dict1 = "root:root" ascii
        $dict2 = "admin:admin" ascii
        $dict3 = "user:user" ascii
        $scan = "connect" ascii
        $spread = "scp" ascii
    condition:
        (any of ($ssh*) and any of ($auth*) and any of ($dict*)) or
        (any of ($ssh*) and $scan and $spread)
}

// ============================================================================
// Cryptocurrency Mining Botnets
// ============================================================================

rule Linux_Botnet_Cryptominer {
    meta:
        description = "Detects cryptomining botnet activity"
        author = "YARA-EDR"
        severity = "high"
        category = "cryptominer"
    strings:
        $pool1 = "stratum+tcp://" ascii
        $pool2 = "stratum+ssl://" ascii
        $pool3 = "pool." ascii
        $miner1 = "xmrig" ascii nocase
        $miner2 = "cpuminer" ascii nocase
        $miner3 = "ccminer" ascii nocase
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $spread1 = "masscan" ascii
        $spread2 = "nmap" ascii
        $exploit = "CVE-" ascii
    condition:
        (any of ($pool*) and any of ($miner*, $algo*)) and any of ($spread*, $exploit)
}

rule Linux_Botnet_Kinsing {
    meta:
        description = "Detects Kinsing cryptomining botnet"
        author = "YARA-EDR"
        severity = "critical"
        category = "cryptominer"
    strings:
        $s1 = "kinsing" ascii nocase
        $s2 = "kdevtmpfsi" ascii
        $s3 = "libsystem.so" ascii
        $docker = "docker" ascii
        $redis = "redis" ascii
        $k8s = "kubernetes" ascii
        $miner = "xmrig" ascii nocase
        $curl = "curl" ascii
        $tmp = "/tmp/" ascii
    condition:
        any of ($s*) or
        (any of ($docker, $redis, $k8s) and $miner and any of ($curl, $tmp))
}

// ============================================================================
// DDoS Attack Tools
// ============================================================================

rule Linux_DDoS_Tool_LOIC {
    meta:
        description = "Detects LOIC (Low Orbit Ion Cannon) variants"
        author = "YARA-EDR"
        severity = "high"
        category = "ddos_tool"
    strings:
        $s1 = "LOIC" ascii nocase
        $s2 = "Low Orbit Ion Cannon" ascii nocase
        $s3 = "HOIC" ascii nocase
        $tcp = "TCP flood" ascii nocase
        $udp = "UDP flood" ascii nocase
        $http = "HTTP flood" ascii nocase
    condition:
        any of ($s*) or 2 of ($tcp, $udp, $http)
}

rule Linux_DDoS_Tool_Slowloris {
    meta:
        description = "Detects Slowloris DDoS tool"
        author = "YARA-EDR"
        severity = "high"
        category = "ddos_tool"
    strings:
        $s1 = "slowloris" ascii nocase
        $s2 = "Slowloris" ascii
        $s3 = "slow HTTP" ascii nocase
        $keep = "keep-alive" ascii nocase
        $partial = "X-a:" ascii
        $sleep = "sleep" ascii
        $socket = "socket" ascii
    condition:
        any of ($s*) or ($keep and $partial and $sleep)
}

rule Linux_DDoS_Tool_Hping {
    meta:
        description = "Detects hping/hping3 flood tool"
        author = "YARA-EDR"
        severity = "medium"
        category = "ddos_tool"
    strings:
        $s1 = "hping" ascii
        $s2 = "hping3" ascii
        $flood = "--flood" ascii
        $syn = "-S" ascii
        $rand = "--rand-source" ascii
        $spoof = "-a" ascii
    condition:
        any of ($s*) and any of ($flood, $rand)
}

rule Linux_DDoS_Tool_Generic {
    meta:
        description = "Detects generic DDoS attack patterns"
        author = "YARA-EDR"
        severity = "high"
        category = "ddos_tool"
    strings:
        $flood1 = "syn_flood" ascii
        $flood2 = "udp_flood" ascii
        $flood3 = "icmp_flood" ascii
        $flood4 = "http_flood" ascii
        $flood5 = "dns_amplification" ascii
        $flood6 = "ntp_amplification" ascii
        $flood7 = "ssdp_amplification" ascii
        $raw1 = "SOCK_RAW" ascii
        $raw2 = "IPPROTO_RAW" ascii
        $spoof = "IP_HDRINCL" ascii
        $target = "target" ascii
        // removed port
    condition:
        uint32(0) == 0x464c457f and
        (2 of ($flood*) or (any of ($raw*) and $spoof and $target))
}

// ============================================================================
// Ircbot/Shellbot
// ============================================================================

rule Linux_Botnet_Shellbot {
    meta:
        description = "Detects Perl/Shell IRC bots"
        author = "YARA-EDR"
        severity = "high"
        category = "botnet"
    strings:
        $perl = "#!/usr/bin/perl" ascii
        $irc1 = "IO::Socket::INET" ascii
        $irc2 = "PRIVMSG" ascii
        $irc3 = "NICK " ascii
        $irc4 = "JOIN #" ascii
        $cmd1 = "portscanner" ascii
        $cmd2 = "portscan" ascii
        $cmd3 = "udpflood" ascii
        $cmd4 = "tcpflood" ascii
        $back = "backdoor" ascii nocase
        $sys = "system(" ascii
    condition:
        ($perl and 2 of ($irc*) and any of ($cmd*)) or
        ($perl and any of ($irc*) and $back and $sys)
}

// ============================================================================
// Backdoor Trojans
// ============================================================================

rule Linux_Botnet_Backdoor_Chaos {
    meta:
        description = "Detects Chaos backdoor/RAT"
        author = "YARA-EDR"
        severity = "critical"
        category = "backdoor"
    strings:
        $s1 = "chaos" ascii nocase
        $s2 = "Chaos" ascii
        $go = "runtime.main" ascii
        $rev = "reverse" ascii
        $shell = "/bin/sh" ascii
        $c2 = "beacon" ascii nocase
    condition:
        uint32(0) == 0x464c457f and
        (($s1 or $s2) and $go and any of ($rev, $shell, $c2))
}

rule Linux_Botnet_Backdoor_Reptile {
    meta:
        description = "Detects Reptile LKM rootkit"
        author = "YARA-EDR"
        severity = "critical"
        category = "rootkit"
    strings:
        $s1 = "reptile" ascii nocase
        $s2 = "KHOOK" ascii
        $s3 = "REPTILE" ascii
        $hide1 = "hide_" ascii
        $hide2 = "hidden" ascii
        $lkm1 = "init_module" ascii
        $lkm2 = "cleanup_module" ascii
        // removed hook
    condition:
        uint32(0) == 0x464c457f and
        (any of ($s*) or (any of ($hide*) and all of ($lkm*)))
}

// ============================================================================
// C2 Communication Patterns
// ============================================================================

rule Linux_Botnet_C2_DNS {
    meta:
        description = "Detects DNS-based C2 communication"
        author = "YARA-EDR"
        severity = "high"
        category = "c2"
    strings:
        $dns1 = "res_query" ascii
        $dns2 = "res_search" ascii
        $dns3 = "__res_" ascii
        $type1 = "TXT" ascii
        $type2 = "CNAME" ascii
        $type3 = "MX" ascii
        $b64 = "base64" ascii
        $enc = "decode" ascii
        $subdomain = "%s.%s" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($dns*) and any of ($type*) and any of ($b64, $enc, $subdomain))
}

rule Linux_Botnet_C2_HTTP {
    meta:
        description = "Detects HTTP-based C2 communication"
        author = "YARA-EDR"
        severity = "medium"
        category = "c2"
    strings:
        $http1 = "curl" ascii
        $http2 = "wget" ascii
        $http3 = "libcurl" ascii
        $ua = "User-Agent" ascii
        $post = "POST" ascii
        $beacon = "beacon" ascii nocase
        $poll = "poll" ascii
        $sleep = "sleep" ascii
        $jitter = "jitter" ascii nocase
    condition:
        uint32(0) == 0x464c457f and
        (any of ($http*) and $ua and $post and any of ($beacon, $poll)) or
        (any of ($http*) and $sleep and $jitter)
}
