/*
    Linux Privilege Escalation Detection Rules
    Detects exploit tools, techniques, and known privilege escalation exploits
    Author: YARA-EDR
*/

import "elf"

// ============================================================================
// Privilege Escalation Enumeration Tools
// ============================================================================

rule Linux_PrivEsc_LinPEAS {
    meta:
        description = "Detects LinPEAS privilege escalation enumeration script"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc_tool"
    strings:
        $s1 = "linpeas" ascii nocase
        $s2 = "LinPeas" ascii
        $s3 = "ADVISORY: " ascii
        $s4 = "99% a]]]]]]]]]]]]]]]]]]]PE" ascii
        $s5 = "Cron jobs" ascii
        $s6 = "SUID" ascii
        $s7 = "Sudo version" ascii
        $banner = "Linux Privilege Escalation" ascii
        $author = "carlospolop" ascii
    condition:
        4 of them
}

rule Linux_PrivEsc_LinEnum {
    meta:
        description = "Detects LinEnum enumeration script"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc_tool"
    strings:
        $s1 = "LinEnum" ascii
        $s2 = "LES=" ascii
        $s3 = "LOCAL LINUX ENUMERATION & PRIVILEGE ESCALATION SCRIPT" ascii
        $s4 = "kernel exploits" ascii nocase
        $s5 = "world-writable" ascii
        $reboot = "@reboot_user" ascii
    condition:
        3 of them
}

rule Linux_PrivEsc_Linux_Exploit_Suggester {
    meta:
        description = "Detects Linux Exploit Suggester tools"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc_tool"
    strings:
        $s1 = "linux-exploit-suggester" ascii nocase
        $s2 = "LES2" ascii
        $s3 = "Kernel local privilege escalation" ascii
        $s4 = "CVE-" ascii
        $s5 = "msfmodule" ascii
        $s6 = "Available information:" ascii
        $check = "kernel_version" ascii
    condition:
        3 of them
}

rule Linux_PrivEsc_PSPY {
    meta:
        description = "Detects pspy process monitoring tool"
        author = "YARA-EDR"
        severity = "medium"
        category = "privesc_tool"
    strings:
        $s1 = "pspy" ascii
        $s2 = "inotify_add_watch" ascii
        $s3 = "/proc/" ascii
        $s4 = "UID=" ascii
        $go1 = "main.main" ascii
        $go2 = "runtime.gopanic" ascii
    condition:
        uint32(0) == 0x464c457f and (($s1 and 2 of ($s*)) or (all of ($go*) and 2 of ($s*)))
}

rule Linux_PrivEsc_Unix_PrivEsc_Check {
    meta:
        description = "Detects unix-privesc-check script"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc_tool"
    strings:
        $s1 = "unix-privesc-check" ascii
        $s2 = "World Writable" ascii
        $s3 = "Checking for password" ascii
        $s4 = "SUID/SGID" ascii
        $s5 = "sudo configuration" ascii
        $s6 = "WARNING:" ascii
    condition:
        3 of them
}

rule Linux_PrivEsc_BeRoot {
    meta:
        description = "Detects BeRoot privilege escalation tool"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc_tool"
    strings:
        $s1 = "beroot" ascii nocase
        $s2 = "GTFOBins" ascii
        $s3 = "find_sudoers" ascii
        $s4 = "find_suid_bins" ascii
        $s5 = "check_nfs_root_squashing" ascii
        $py = "#!/usr/bin/python" ascii
    condition:
        3 of them or ($py and 2 of ($s*))
}

// ============================================================================
// Kernel Exploits - CVE-Based Detection
// ============================================================================

rule Linux_Exploit_DirtyPipe_CVE_2022_0847 {
    meta:
        description = "Detects DirtyPipe kernel exploit (CVE-2022-0847)"
        author = "YARA-EDR"
        severity = "critical"
        category = "kernel_exploit"
        cve = "CVE-2022-0847"
    strings:
        $s1 = "PIPE_BUF_FLAG_CAN_MERGE" ascii
        $s2 = "splice" ascii
        $s3 = "/etc/passwd" ascii
        $s4 = "page_offset" ascii
        $pipe1 = "pipe2" ascii
        $pipe2 = "pipe(" ascii
        $suid = "/usr/bin/su" ascii
    condition:
        uint32(0) == 0x464c457f and (($s1 and $s2) or (3 of ($s*)) or (any of ($pipe*) and $suid))
}

rule Linux_Exploit_DirtyCow_CVE_2016_5195 {
    meta:
        description = "Detects DirtyCow kernel exploit (CVE-2016-5195)"
        author = "YARA-EDR"
        severity = "critical"
        category = "kernel_exploit"
        cve = "CVE-2016-5195"
    strings:
        $s1 = "dirtycow" ascii nocase
        $s2 = "MADV_DONTNEED" ascii
        $s3 = "/proc/self/mem" ascii
        $s4 = "ptrace" ascii
        $s5 = "madvise" ascii
        $s6 = "PTRACE_POKETEXT" ascii
        $s7 = "/etc/passwd" ascii
        $race = { E8 ?? ?? ?? ?? 48 89 ?? 48 8D ?? ?? ?? ?? ?? E8 }
    condition:
        uint32(0) == 0x464c457f and (4 of ($s*) or ($race and 2 of ($s*)))
}

rule Linux_Exploit_Polkit_CVE_2021_4034 {
    meta:
        description = "Detects PwnKit Polkit exploit (CVE-2021-4034)"
        author = "YARA-EDR"
        severity = "critical"
        category = "polkit_exploit"
        cve = "CVE-2021-4034"
    strings:
        $s1 = "pkexec" ascii
        $s2 = "GCONV_PATH" ascii
        $s3 = ".so" ascii
        $s4 = "pwnkit" ascii nocase
        $path = "GCONV_PATH=." ascii
        $shell = "/bin/sh" ascii
    condition:
        uint32(0) == 0x464c457f and (($s1 and $s2 and $s3) or $s4 or ($path and $shell))
}

rule Linux_Exploit_Sudo_Baron_Samedit_CVE_2021_3156 {
    meta:
        description = "Detects Sudo Baron Samedit exploit (CVE-2021-3156)"
        author = "YARA-EDR"
        severity = "critical"
        category = "sudo_exploit"
        cve = "CVE-2021-3156"
    strings:
        $s1 = "sudoedit" ascii
        $s2 = "-s" ascii
        $s3 = "heap overflow" ascii nocase
        $s4 = "service_user" ascii
        $s5 = "nss_load_library" ascii
        $s6 = "baron samedit" ascii nocase
        $s7 = "libnss" ascii
        $payload = { 41 ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 }
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or ($payload and any of ($s*)))
}

rule Linux_Exploit_OverlayFS_CVE_2023_0386 {
    meta:
        description = "Detects OverlayFS privilege escalation exploit (CVE-2023-0386)"
        author = "YARA-EDR"
        severity = "critical"
        category = "kernel_exploit"
        cve = "CVE-2023-0386"
    strings:
        $s1 = "overlayfs" ascii nocase
        $s2 = "ovl_copy_up" ascii
        $s3 = "setuid" ascii
        $s4 = "mknod" ascii
        $s5 = "/tmp/" ascii
        $fuse = "fuse" ascii
        $mount = "mount" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) and any of ($fuse, $mount))
}

rule Linux_Exploit_NetFilter_CVE_2023_32233 {
    meta:
        description = "Detects NetFilter use-after-free exploit (CVE-2023-32233)"
        author = "YARA-EDR"
        severity = "critical"
        category = "kernel_exploit"
        cve = "CVE-2023-32233"
    strings:
        $s1 = "nf_tables" ascii
        $s2 = "nft_" ascii
        $s3 = "NFTA_" ascii
        $s4 = "use-after-free" ascii nocase
        $s5 = "netfilter" ascii
        $s6 = "NFT_MSG" ascii
        $spray = "msg_msg" ascii
        $heap = "kmalloc" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or (any of ($spray, $heap) and 2 of ($s*)))
}

rule Linux_Exploit_StackRot_CVE_2023_3269 {
    meta:
        description = "Detects StackRot kernel exploit (CVE-2023-3269)"
        author = "YARA-EDR"
        severity = "critical"
        category = "kernel_exploit"
        cve = "CVE-2023-3269"
    strings:
        $s1 = "stackrot" ascii nocase
        $s2 = "maple_tree" ascii
        $s3 = "VMA" ascii
        $s4 = "mmap" ascii
        $s5 = "page fault" ascii nocase
        $s6 = "rcu_read" ascii
        $s7 = "mmap_lock" ascii
    condition:
        uint32(0) == 0x464c457f and (($s1) or (4 of ($s*)))
}

rule Linux_Exploit_GameOver_CVE_2023_0179 {
    meta:
        description = "Detects nftables GameOver exploit (CVE-2023-0179)"
        author = "YARA-EDR"
        severity = "critical"
        category = "kernel_exploit"
        cve = "CVE-2023-0179"
    strings:
        $s1 = "nftables" ascii
        $s2 = "nft_payload" ascii
        $s3 = "buffer overflow" ascii nocase
        $s4 = "NFT_PAYLOAD" ascii
        $s5 = "game over" ascii nocase
        $spray = "setxattr" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or ($spray and 2 of ($s*)))
}

// ============================================================================
// SUID/SGID Binary Abuse
// ============================================================================

rule Linux_PrivEsc_SUID_Abuse {
    meta:
        description = "Detects SUID binary abuse techniques"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc"
    strings:
        $suid1 = "find / -perm -4000" ascii
        $suid2 = "find / -perm -u=s" ascii
        $suid3 = "find / -perm /4000" ascii
        $gtfo1 = "gtfobins" ascii nocase
        $gtfo2 = "GTFOBins" ascii
        $bins1 = "/usr/bin/vim" ascii
        $bins2 = "/usr/bin/nano" ascii
        $bins3 = "/usr/bin/less" ascii
        $bins4 = "/usr/bin/find" ascii
        $bins5 = "/usr/bin/awk" ascii
        $bins6 = "/usr/bin/python" ascii
        $bins7 = "/usr/bin/perl" ascii
        $shell = "-exec /bin/sh" ascii
    condition:
        2 of ($suid*) or any of ($gtfo*) or (2 of ($bins*) and $shell)
}

rule Linux_PrivEsc_Sudo_Abuse {
    meta:
        description = "Detects sudo misconfiguration abuse"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc"
    strings:
        $sudo1 = "sudo -l" ascii
        $sudo2 = "sudoers" ascii
        $sudo3 = "NOPASSWD" ascii
        $sudo4 = "(ALL : ALL)" ascii
        $bypass1 = "sudo -u#-1" ascii
        $bypass2 = "sudo -u#4294967295" ascii
        $env1 = "LD_PRELOAD" ascii
        $env2 = "LD_LIBRARY_PATH" ascii
    condition:
        (2 of ($sudo*) and any of ($bypass*, $env*)) or any of ($bypass*)
}

rule Linux_PrivEsc_Capabilities_Abuse {
    meta:
        description = "Detects Linux capabilities abuse for privilege escalation"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc"
    strings:
        $cap1 = "getcap" ascii
        $cap2 = "setcap" ascii
        $cap3 = "cap_setuid" ascii
        $cap4 = "cap_setgid" ascii
        $cap5 = "cap_sys_admin" ascii
        $cap6 = "cap_dac_override" ascii
        $cap7 = "cap_sys_ptrace" ascii
        $cap8 = "cap_net_admin" ascii
        $find = "getcap -r" ascii
        $exploit = "cap_setuid+ep" ascii
    condition:
        ($find and 2 of ($cap*)) or $exploit or (4 of ($cap*))
}

// ============================================================================
// Cron and Scheduled Task Abuse
// ============================================================================

rule Linux_PrivEsc_Cron_Abuse {
    meta:
        description = "Detects cron job abuse for privilege escalation"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc"
    strings:
        $cron1 = "/etc/crontab" ascii
        $cron2 = "/etc/cron.d" ascii
        $cron3 = "/var/spool/cron" ascii
        $cron4 = "crontab -l" ascii
        $wild1 = "tar cf" ascii
        $wild2 = "--checkpoint" ascii
        $wild3 = "rsync" ascii
        $wild4 = "*" ascii
        $write1 = "world-writable" ascii nocase
        $write2 = "chmod 777" ascii
    condition:
        (any of ($cron*) and any of ($wild*) and any of ($write*)) or
        (2 of ($cron*) and 2 of ($wild*))
}

rule Linux_PrivEsc_PATH_Hijack {
    meta:
        description = "Detects PATH hijacking for privilege escalation"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc"
    strings:
        $path1 = "PATH=" ascii
        $path2 = "/tmp" ascii
        $path3 = "export PATH" ascii
        $rel1 = "service" ascii
        $rel2 = "curl" ascii
        $rel3 = "wget" ascii
        $rel4 = "python" ascii
        $mal1 = "/bin/sh" ascii
        $mal2 = "/bin/bash" ascii
        $perm1 = "chmod +x" ascii
    condition:
        (any of ($path*) and any of ($rel*) and any of ($mal*)) or
        ($path3 and $perm1 and any of ($mal*))
}

// ============================================================================
// Service/Systemd Abuse
// ============================================================================

rule Linux_PrivEsc_Service_Abuse {
    meta:
        description = "Detects systemd service abuse for privilege escalation"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc"
    strings:
        $svc1 = "systemctl" ascii
        $svc2 = ".service" ascii
        $svc3 = "/etc/systemd" ascii
        $svc4 = "[Service]" ascii
        $exec1 = "ExecStart" ascii
        $exec2 = "ExecStop" ascii
        $user1 = "User=root" ascii
        $write = "writable" ascii nocase
        $link = "systemctl link" ascii
    condition:
        (2 of ($svc*) and any of ($exec*) and any of ($user*, $write*)) or $link
}

rule Linux_PrivEsc_NFS_Root_Squash {
    meta:
        description = "Detects NFS root squash misconfiguration exploitation"
        author = "YARA-EDR"
        severity = "high"
        category = "privesc"
    strings:
        $nfs1 = "/etc/exports" ascii
        $nfs2 = "showmount" ascii
        $nfs3 = "no_root_squash" ascii
        $nfs4 = "rw,sync" ascii
        $mount = "mount -t nfs" ascii
        $suid = "chmod u+s" ascii
        $shell = "/bin/bash" ascii
    condition:
        ($nfs3) or (2 of ($nfs*) and any of ($mount, $suid, $shell))
}

// ============================================================================
// Docker/Container Escape
// ============================================================================

rule Linux_PrivEsc_Docker_Escape {
    meta:
        description = "Detects Docker escape techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $docker1 = "docker.sock" ascii
        $docker2 = "/var/run/docker.sock" ascii
        $docker3 = "docker exec" ascii
        $docker4 = "--privileged" ascii
        $docker5 = "-v /:/host" ascii
        $escape1 = "nsenter" ascii
        $escape2 = "cgroup" ascii
        $escape3 = "release_agent" ascii
        $escape4 = "notify_on_release" ascii
        $chroot = "chroot /host" ascii
    condition:
        (2 of ($docker*)) or (2 of ($escape*)) or $chroot
}

rule Linux_PrivEsc_Container_Breakout {
    meta:
        description = "Detects container breakout attempts"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $s1 = "/.dockerenv" ascii
        $s2 = "/proc/1/cgroup" ascii
        $s3 = "CAP_SYS_ADMIN" ascii
        $s4 = "mount -t cgroup" ascii
        $s5 = "release_agent" ascii
        $s6 = "notify_on_release" ascii
        $s7 = "/sys/fs/cgroup" ascii
        $debug = "SYS_PTRACE" ascii
    condition:
        (3 of them) or ($s5 and $s6)
}

// ============================================================================
// Kernel Module Loading
// ============================================================================

rule Linux_PrivEsc_Kernel_Module_Load {
    meta:
        description = "Detects malicious kernel module loading attempts"
        author = "YARA-EDR"
        severity = "critical"
        category = "privesc"
    strings:
        $s1 = "insmod" ascii
        $s2 = "modprobe" ascii
        $s3 = "init_module" ascii
        $s4 = "finit_module" ascii
        $s5 = ".ko" ascii
        $root1 = "commit_creds" ascii
        $root2 = "prepare_kernel_cred" ascii
    condition:
        uint32(0) == 0x464c457f and
        ((any of ($s1, $s2) and any of ($root*)) or ($s3 and $s4 and any of ($root*)) or ($s5 and any of ($root*)))
}

// ============================================================================
// Memory Corruption Exploitation
// ============================================================================

rule Linux_PrivEsc_ROP_Chain {
    meta:
        description = "Detects ROP chain exploitation attempts"
        author = "YARA-EDR"
        severity = "critical"
        category = "exploit"
    strings:
        $rop1 = "pop rdi" ascii
        $rop2 = "pop rsi" ascii
        $rop3 = "pop rdx" ascii
        $rop4 = "ret" ascii
        $gadget1 = "ROPgadget" ascii
        $gadget2 = "ropper" ascii
        $libc = "libc.so" ascii
        $system = "system@" ascii
    condition:
        (3 of ($rop*) and any of ($gadget*)) or
        (any of ($gadget*) and $libc and $system)
}

rule Linux_PrivEsc_Heap_Exploit {
    meta:
        description = "Detects heap exploitation techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "exploit"
    strings:
        $s1 = "house of" ascii nocase
        $s2 = "tcache" ascii
        $s3 = "fastbin" ascii
        $s4 = "unsorted bin" ascii
        $s5 = "__malloc_hook" ascii
        $s6 = "__free_hook" ascii
        $s7 = "fake chunk" ascii nocase
        $s8 = "double free" ascii nocase
        $uaf = "use-after-free" ascii nocase
    condition:
        3 of them
}

// ============================================================================
// Generic Privilege Escalation Indicators
// ============================================================================

rule Linux_PrivEsc_Generic_Indicators {
    meta:
        description = "Generic indicators of privilege escalation activity"
        author = "YARA-EDR"
        severity = "medium"
        category = "privesc"
    strings:
        $enum1 = "id" ascii
        $enum2 = "whoami" ascii
        $enum3 = "uname -a" ascii
        $enum4 = "cat /etc/passwd" ascii
        $enum5 = "cat /etc/shadow" ascii
        $enum6 = "/etc/sudoers" ascii
        $check1 = "find / -perm" ascii
        $check2 = "getcap -r /" ascii
        $check3 = "cat /etc/crontab" ascii
        $check4 = "ls -la /etc/cron" ascii
        $priv1 = "setuid(0)" ascii
        $priv2 = "setgid(0)" ascii
        $priv3 = "execve" ascii
    condition:
        (4 of ($enum*, $check*)) or (all of ($priv*))
}
