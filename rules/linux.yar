/*
    Linux-Specific YARA Rules for EDR
    Detects common Linux malware, rootkits, backdoors, and suspicious patterns
*/

rule Linux_Rootkit_Strings {
    meta:
        description = "Detects common Linux rootkit strings"
        author = "YARA-EDR"
        severity = "critical"
        category = "rootkit"
    strings:
        $s1 = "/proc/net/tcp" ascii
        $s2 = "hide_pid" ascii
        $s3 = "rootkit" ascii nocase
        $s4 = "/dev/null" ascii
        $s5 = "LD_PRELOAD" ascii
        $s6 = "__libc_start_main" ascii
        $s7 = "syscall_table" ascii
        $s8 = "sys_call_table" ascii
        $s9 = "/etc/ld.so.preload" ascii
        $s10 = "hide_module" ascii
    condition:
        uint32(0) == 0x464c457f and 4 of them
}

rule Linux_Backdoor_Reverse_Shell {
    meta:
        description = "Detects reverse shell patterns in Linux binaries"
        author = "YARA-EDR"
        severity = "high"
        category = "backdoor"
    strings:
        $socket = "socket" ascii
        $connect = "connect" ascii
        $dup2 = "dup2" ascii
        $execve = "execve" ascii
        $bin_sh = "/bin/sh" ascii
        $bin_bash = "/bin/bash" ascii
        $dev_tcp = "/dev/tcp/" ascii
        $nc_e = "nc -e" ascii
        $bash_i = "bash -i" ascii
        $sh_i = "sh -i" ascii
        $perl_socket = "use Socket" ascii
        $python_socket = "import socket" ascii
        $mkfifo = "mkfifo" ascii
    condition:
        (uint32(0) == 0x464c457f and 3 of ($socket, $connect, $dup2, $execve, $bin_sh, $bin_bash)) or
        any of ($dev_tcp, $nc_e, $bash_i, $sh_i, $perl_socket, $python_socket, $mkfifo)
}

rule Linux_Miner_XMRig {
    meta:
        description = "Detects XMRig and similar cryptocurrency miners"
        author = "YARA-EDR"
        severity = "medium"
        category = "cryptominer"
    strings:
        $xmrig1 = "xmrig" ascii nocase
        $xmrig2 = "XMRig" ascii
        $pool1 = "stratum+tcp://" ascii
        $pool2 = "stratum+ssl://" ascii
        $pool3 = "pool.minexmr" ascii
        $pool4 = "pool.supportxmr" ascii
        $pool5 = "xmrpool.eu" ascii
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $wallet = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        $config1 = "\"algo\":" ascii
        $config2 = "\"url\":" ascii
        $config3 = "\"user\":" ascii
    condition:
        2 of them
}

rule Linux_Webshell_PHP {
    meta:
        description = "Detects PHP webshells commonly found on Linux servers"
        author = "YARA-EDR"
        severity = "high"
        category = "webshell"
    strings:
        $php = "<?php" ascii nocase
        $eval = "eval(" ascii
        $base64 = "base64_decode(" ascii
        $system = "system(" ascii
        $shell_exec = "shell_exec(" ascii
        $passthru = "passthru(" ascii
        $exec = /\bexec\s*\(/ ascii
        $popen = "popen(" ascii
        $proc_open = "proc_open(" ascii
        $assert = "assert(" ascii
        $preg_replace = "preg_replace" ascii
        $cmd = "$_REQUEST" ascii
        $cmd2 = "$_GET" ascii
        $cmd3 = "$_POST" ascii
        $c99 = "c99shell" ascii nocase
        $r57 = "r57shell" ascii nocase
        $wso = "WSO" ascii
    condition:
        $php and (
            (any of ($eval, $base64, $assert) and any of ($cmd, $cmd2, $cmd3)) or
            (2 of ($system, $shell_exec, $passthru, $exec, $popen, $proc_open, $preg_replace)) or
            any of ($c99, $r57, $wso)
        )
}

rule Linux_Drovorub_APT28 {
    meta:
        description = "Detects Drovorub malware associated with APT28"
        author = "YARA-EDR"
        severity = "critical"
        category = "apt"
    strings:
        $s1 = "do_fork" ascii
        $s2 = "module_hidden" ascii
        $s3 = "/proc/net/packet" ascii
        $s4 = "hide_proc" ascii
        $s5 = "rootfs" ascii
        $s6 = "penguin" ascii
        $s7 = "bear" ascii
        $kernel1 = "init_module" ascii
        $kernel2 = "cleanup_module" ascii
    condition:
        uint32(0) == 0x464c457f and 4 of them
}

rule Linux_ELF_Packed_UPX {
    meta:
        description = "Detects UPX packed ELF binaries (potentially suspicious)"
        author = "YARA-EDR"
        severity = "low"
        category = "packer"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = "$Info: This file is packed with the UPX" ascii
    condition:
        uint32(0) == 0x464c457f and any of them
}

rule Linux_Suspicious_Static_Keys {
    meta:
        description = "Detects hardcoded SSH keys or credentials"
        author = "YARA-EDR"
        severity = "high"
        category = "credentials"
    strings:
        $ssh_priv = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ssh_priv2 = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $ssh_priv3 = "-----BEGIN DSA PRIVATE KEY-----" ascii
        $ssh_priv4 = "-----BEGIN EC PRIVATE KEY-----" ascii
        $aws_key = /AKIA[0-9A-Z]{16}/ ascii
        $password = /password\s*=\s*['\"][^'\"]{8,}['\"]/ ascii nocase
    condition:
        any of them
}

rule Linux_BPFDoor_Backdoor {
    meta:
        description = "Detects BPFDoor backdoor malware"
        author = "YARA-EDR"
        severity = "critical"
        category = "backdoor"
    strings:
        $bpf1 = "BPF_LD" ascii
        $bpf2 = "SO_ATTACH_FILTER" ascii
        $bpf3 = "setsockopt" ascii
        $magic = { 21 00 00 00 }
        $s1 = "/var/run/haldrund.pid" ascii
        $s2 = "/dev/shm" ascii
        $s3 = "packet_recvmsg" ascii
        $prctl = "prctl" ascii
        $setenv = "setenv" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($bpf*, $magic) or any of ($s1, $s2, $s3) or ($prctl and $setenv))
}

rule Linux_Mirai_Botnet {
    meta:
        description = "Detects Mirai botnet variants"
        author = "YARA-EDR"
        severity = "critical"
        category = "botnet"
    strings:
        $s1 = "/bin/busybox" ascii
        $s2 = "MIRAI" ascii
        $s3 = "TSUNAMI" ascii
        $s4 = "LOLNOGTFO" ascii
        $telnet = "telnet" ascii
        $busybox = "busybox" ascii
        $scanner = "scanner" ascii
        $killer = "killer" ascii
        $attack = "attack" ascii
        $botnet = "botnet" ascii nocase
        $cnc = { 68 ?? ?? ?? ?? 68 ?? ?? 00 00 }
        $xor = { 31 ?? 31 ?? 31 ?? }
    condition:
        uint32(0) == 0x464c457f and (
            any of ($s1, $s2, $s3, $s4) or
            (3 of ($telnet, $busybox, $scanner, $killer, $attack, $botnet, $cnc, $xor))
        )
}

rule Linux_Persistence_Cron {
    meta:
        description = "Detects scripts attempting to establish cron persistence"
        author = "YARA-EDR"
        severity = "medium"
        category = "persistence"
    strings:
        $cron1 = "/etc/crontab" ascii
        $cron2 = "/etc/cron.d/" ascii
        $cron3 = "/var/spool/cron" ascii
        $cron4 = "crontab -" ascii
        $cron5 = "/etc/cron.hourly" ascii
        $cron6 = "/etc/cron.daily" ascii
        $cmd1 = "curl" ascii
        $cmd2 = "wget" ascii
        $cmd3 = "bash" ascii
        $cmd4 = "sh -c" ascii
        $pipe = "|" ascii
    condition:
        any of ($cron*) and any of ($cmd*) and $pipe
}

rule Linux_LD_Preload_Injection {
    meta:
        description = "Detects LD_PRELOAD injection techniques"
        author = "YARA-EDR"
        severity = "high"
        category = "injection"
    strings:
        $preload1 = "LD_PRELOAD" ascii
        $preload2 = "/etc/ld.so.preload" ascii
        $hook1 = "dlsym" ascii
        $hook2 = "RTLD_NEXT" ascii
        $func1 = "readdir" ascii
        $func2 = "fopen" ascii
        $func3 = "open" ascii
        $func4 = "stat" ascii
        $func5 = "lstat" ascii
        $func6 = "write" ascii
    condition:
        uint32(0) == 0x464c457f and
        any of ($preload*) and
        any of ($hook*) and
        2 of ($func*)
}

rule Linux_Kernel_Module_Suspicious {
    meta:
        description = "Detects suspicious Linux kernel modules"
        author = "YARA-EDR"
        severity = "high"
        category = "rootkit"
    strings:
        $init = "init_module" ascii
        $cleanup = "cleanup_module" ascii
        $syscall = "sys_call_table" ascii
        $hide1 = "list_del" ascii
        $hide2 = "kobject" ascii
        $proc = "proc_create" ascii
        $netfilter = "nf_register" ascii
        $hook = "register_kprobe" ascii
    condition:
        uint32(0) == 0x464c457f and
        $init and $cleanup and
        (any of ($syscall, $hide1, $hide2, $hook) or ($proc and $netfilter))
}

rule Linux_Ransomware_Generic {
    meta:
        description = "Detects generic Linux ransomware patterns"
        author = "YARA-EDR"
        severity = "critical"
        category = "ransomware"
    strings:
        $ransom1 = "Your files have been encrypted" ascii nocase
        $ransom2 = "bitcoin" ascii nocase
        $ransom3 = "decrypt" ascii nocase
        $ransom4 = "ransom" ascii nocase
        $ransom5 = ".onion" ascii
        $ext1 = ".encrypted" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".crypted" ascii
        $crypto1 = "AES" ascii
        $crypto2 = "RSA" ascii
        $crypto3 = "EVP_" ascii
        $files = "find / -type f" ascii
    condition:
        2 of ($ransom*) or
        (any of ($ext*) and any of ($crypto*) and $files)
}

rule Linux_Tsunami_Backdoor {
    meta:
        description = "Detects Tsunami/Kaiten IRC backdoor"
        author = "YARA-EDR"
        severity = "critical"
        category = "backdoor"
    strings:
        $irc1 = "PRIVMSG" ascii
        $irc2 = "NICK" ascii
        $irc3 = "JOIN" ascii
        $irc4 = "PING" ascii
        $irc5 = "PONG" ascii
        $cmd1 = "TSUNAMI" ascii
        $cmd2 = "UNKNOWN" ascii
        $cmd3 = "JUNK" ascii
        $cmd4 = "UDP" ascii
        $cmd5 = "PAN" ascii
        $func = "sendto" ascii
    condition:
        uint32(0) == 0x464c457f and
        3 of ($irc*) and
        2 of ($cmd*) and
        $func
}

rule Linux_Suspicious_Process_Injection {
    meta:
        description = "Detects process injection techniques on Linux"
        author = "YARA-EDR"
        severity = "high"
        category = "injection"
    strings:
        $ptrace = "ptrace" ascii
        $mem = "/proc/self/mem" ascii
        $maps = "/proc/self/maps" ascii
        $inject1 = "PTRACE_ATTACH" ascii
        $inject2 = "PTRACE_POKETEXT" ascii
        $inject3 = "PTRACE_POKEDATA" ascii
        $inject4 = "PTRACE_SETREGS" ascii
        $inject5 = "PTRACE_CONT" ascii
        $mmap = "mmap" ascii
        $mprotect = "mprotect" ascii
    condition:
        uint32(0) == 0x464c457f and
        $ptrace and
        (2 of ($inject*) or ($mmap and $mprotect and any of ($mem, $maps)))
}

rule Linux_Shikitega_Malware {
    meta:
        description = "Detects Shikitega Linux malware"
        author = "YARA-EDR"
        severity = "critical"
        category = "malware"
    strings:
        $shell = "#!/bin/sh" ascii
        $curl = "curl" ascii
        $wget = "wget" ascii
        $chmod = "chmod" ascii
        $tmp = "/tmp/" ascii
        $dev_shm = "/dev/shm" ascii
        $cron = "crontab" ascii
        $shikata = { 31 ?? 83 ?? ?? 81 ?? ?? ?? ?? ?? }
    condition:
        ($shell and 3 of ($curl, $wget, $chmod, $tmp, $dev_shm, $cron)) or
        $shikata
}
