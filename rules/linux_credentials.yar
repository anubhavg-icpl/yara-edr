/*
    Linux Credential Theft Detection Rules
    Detects credential stealers, password dumpers, and authentication attacks
    Author: YARA-EDR
*/

import "elf"

// ============================================================================
// Password File Access
// ============================================================================

rule Linux_Cred_Shadow_Access {
    meta:
        description = "Detects /etc/shadow file access patterns"
        author = "YARA-EDR"
        severity = "critical"
        category = "credential_access"
    strings:
        $shadow1 = "/etc/shadow" ascii
        $shadow2 = "/etc/gshadow" ascii
        $read1 = "fopen" ascii
        $read2 = "open(" ascii
        $read3 = "fread" ascii
        $hash1 = "$1$" ascii
        $hash2 = "$5$" ascii
        $hash3 = "$6$" ascii
        $hash4 = "$y$" ascii
        $crack1 = "john" ascii nocase
        $crack2 = "hashcat" ascii nocase
        $crack3 = "crack" ascii nocase
    condition:
        (any of ($shadow*) and any of ($read*)) or
        (any of ($shadow*) and any of ($hash*)) or
        (any of ($shadow*) and any of ($crack*))
}

rule Linux_Cred_Passwd_Manipulation {
    meta:
        description = "Detects /etc/passwd manipulation"
        author = "YARA-EDR"
        severity = "high"
        category = "credential_access"
    strings:
        $passwd = "/etc/passwd" ascii
        $write1 = "fwrite" ascii
        $write2 = "fputs" ascii
        $write3 = "fprintf" ascii
        $append = ">>" ascii
        $uid0 = ":0:0:" ascii
        // removed unused root
        $backdoor1 = "useradd" ascii
        $backdoor2 = "usermod" ascii
    condition:
        ($passwd and any of ($write*)) or
        ($passwd and $uid0 and any of ($append, $backdoor1, $backdoor2))
}

// ============================================================================
// SSH Credential Theft
// ============================================================================

rule Linux_Cred_SSH_Key_Theft {
    meta:
        description = "Detects SSH private key theft"
        author = "YARA-EDR"
        severity = "critical"
        category = "credential_theft"
    strings:
        $ssh_dir = ".ssh/" ascii
        $id_rsa = "id_rsa" ascii
        $id_dsa = "id_dsa" ascii
        $id_ecdsa = "id_ecdsa" ascii
        $id_ed25519 = "id_ed25519" ascii
        $priv1 = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $priv2 = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $priv3 = "-----BEGIN DSA PRIVATE KEY-----" ascii
        $priv4 = "-----BEGIN EC PRIVATE KEY-----" ascii
        // removed known_hosts
        // removed authorized
        $exfil1 = "curl" ascii
        $exfil2 = "wget" ascii
        $exfil3 = "scp" ascii
        $exfil4 = "nc" ascii
    condition:
        (any of ($priv*)) or
        ($ssh_dir and any of ($id_rsa, $id_dsa, $id_ecdsa, $id_ed25519) and any of ($exfil*))
}

rule Linux_Cred_SSH_Agent_Hijack {
    meta:
        description = "Detects SSH agent hijacking"
        author = "YARA-EDR"
        severity = "critical"
        category = "credential_theft"
    strings:
        $agent1 = "SSH_AUTH_SOCK" ascii
        $agent2 = "ssh-agent" ascii
        $agent3 = "/tmp/ssh-" ascii
        $agent4 = "agent." ascii
        $socket = "socket" ascii
        $connect = "connect" ascii
        // removed enum
        $forward = "ForwardAgent" ascii
    condition:
        (2 of ($agent*) and any of ($socket, $connect)) or
        ($forward and any of ($agent*))
}

// ============================================================================
// Browser Credential Theft
// ============================================================================

rule Linux_Cred_Browser_Theft {
    meta:
        description = "Detects browser credential theft"
        author = "YARA-EDR"
        severity = "high"
        category = "credential_theft"
    strings:
        $chrome1 = ".config/google-chrome" ascii
        $chrome2 = ".config/chromium" ascii
        $chrome3 = "Login Data" ascii
        $chrome4 = "Cookies" ascii
        $firefox1 = ".mozilla/firefox" ascii
        $firefox2 = "logins.json" ascii
        $firefox3 = "key4.db" ascii
        $firefox4 = "cookies.sqlite" ascii
        $decrypt1 = "pycryptodome" ascii
        $decrypt2 = "secretstorage" ascii
        $decrypt3 = "keyring" ascii
        $sqlite = "sqlite3" ascii
        // removed b64
    condition:
        (any of ($chrome*) and any of ($decrypt*, $sqlite)) or
        (any of ($firefox*) and any of ($decrypt*, $sqlite))
}

// ============================================================================
// Keylogging
// ============================================================================

rule Linux_Cred_Keylogger {
    meta:
        description = "Detects Linux keylogger activity"
        author = "YARA-EDR"
        severity = "critical"
        category = "keylogger"
    strings:
        $dev1 = "/dev/input/" ascii
        $dev2 = "/dev/input/event" ascii
        $dev3 = "input_event" ascii
        // removed evdev
        $xinput = "xinput" ascii
        $xlib1 = "XOpenDisplay" ascii
        $xlib2 = "XQueryKeymap" ascii
        $xlib3 = "XGetInputFocus" ascii
        $key1 = "KEY_" ascii
        $key2 = "EV_KEY" ascii
        $log1 = "keylog" ascii nocase
        $log2 = "keystroke" ascii nocase
    condition:
        uint32(0) == 0x464c457f and
        (any of ($dev*) and any of ($key*)) or
        (any of ($xlib*) and any of ($log*)) or
        ($xinput and any of ($log*))
}

rule Linux_Cred_TTY_Snooping {
    meta:
        description = "Detects TTY snooping for credentials"
        author = "YARA-EDR"
        severity = "high"
        category = "credential_theft"
    strings:
        $tty1 = "/dev/pts/" ascii
        $tty2 = "/dev/tty" ascii
        $tty3 = "openpty" ascii
        $tty4 = "forkpty" ascii
        // removed pty
        // removed script
        // removed screen
        $snoop1 = "ttysnoop" ascii
        $snoop2 = "reptyr" ascii
        $hook = "LD_PRELOAD" ascii
    condition:
        (any of ($tty*) and any of ($snoop*)) or
        (any of ($tty*) and $hook)
}

// ============================================================================
// Credential Dumping Tools
// ============================================================================

rule Linux_Cred_Mimipenguin {
    meta:
        description = "Detects mimipenguin credential dumper"
        author = "YARA-EDR"
        severity = "critical"
        category = "credential_dumper"
    strings:
        $s1 = "mimipenguin" ascii nocase
        $s2 = "MimiPenguin" ascii
        $proc1 = "/proc/" ascii
        $proc2 = "/maps" ascii
        $proc3 = "/mem" ascii
        $gdm = "gdm-password" ascii
        $gnome = "gnome-keyring" ascii
        $vsftpd = "vsftpd" ascii
        $apache = "apache2" ascii
        $sshd = "sshd" ascii
    condition:
        any of ($s*) or
        (2 of ($proc*) and 2 of ($gdm, $gnome, $vsftpd, $apache, $sshd))
}

rule Linux_Cred_LaZagne {
    meta:
        description = "Detects LaZagne credential recovery tool"
        author = "YARA-EDR"
        severity = "critical"
        category = "credential_dumper"
    strings:
        $s1 = "lazagne" ascii nocase
        $s2 = "LaZagne" ascii
        $s3 = "laZagne" ascii
        $mod1 = "browsers" ascii
        $mod2 = "chats" ascii
        $mod3 = "databases" ascii
        $mod4 = "mails" ascii
        $mod5 = "memory" ascii
        $mod6 = "sysadmin" ascii
        $mod7 = "wallet" ascii
        $py = "#!/usr/bin/python" ascii
    condition:
        any of ($s*) or
        ($py and 3 of ($mod*))
}

rule Linux_Cred_Truffleproc {
    meta:
        description = "Detects truffleproc memory credential extraction"
        author = "YARA-EDR"
        severity = "high"
        category = "credential_dumper"
    strings:
        $s1 = "truffleproc" ascii nocase
        $s2 = "truffle" ascii nocase
        $mem = "/proc/" ascii
        $maps = "/maps" ascii
        $scan = "memscan" ascii
        $regex1 = "password" ascii nocase
        $regex2 = "passwd" ascii nocase
        $regex3 = "secret" ascii nocase
        $regex4 = "token" ascii nocase
    condition:
        any of ($s*) or
        ($mem and $maps and 2 of ($regex*))
}

// ============================================================================
// Process Memory Credential Extraction
// ============================================================================

rule Linux_Cred_Proc_Memory_Dump {
    meta:
        description = "Detects process memory dumping for credentials"
        author = "YARA-EDR"
        severity = "high"
        category = "credential_access"
    strings:
        $proc1 = "/proc/" ascii
        $proc2 = "/mem" ascii
        $proc3 = "/maps" ascii
        $proc4 = "/cmdline" ascii
        $ptrace = "ptrace" ascii
        $gcore = "gcore" ascii
        $gdb = "gdb" ascii
        $target1 = "sshd" ascii
        $target2 = "sudo" ascii
        $target3 = "su" ascii
        $target4 = "login" ascii
        $target5 = "gdm" ascii
        $target6 = "gnome-keyring" ascii
    condition:
        uint32(0) == 0x464c457f and
        (2 of ($proc*) and any of ($target*)) or
        (any of ($ptrace, $gcore, $gdb) and any of ($target*))
}

// ============================================================================
// GNOME Keyring / KWallet
// ============================================================================

rule Linux_Cred_Keyring_Access {
    meta:
        description = "Detects keyring credential access"
        author = "YARA-EDR"
        severity = "high"
        category = "credential_access"
    strings:
        $gnome1 = "gnome-keyring" ascii
        $gnome2 = "org.gnome.keyring" ascii
        $gnome3 = "libgnome-keyring" ascii
        $gnome4 = "SECRET_COLLECTION" ascii
        $kde1 = "kwallet" ascii
        $kde2 = "kwalletd" ascii
        $kde3 = "org.kde.KWallet" ascii
        $dbus = "dbus" ascii
        $secret = "secretstorage" ascii
        $dump = "dump" ascii nocase
        $extract = "extract" ascii nocase
    condition:
        (any of ($gnome*, $kde*) and any of ($dump, $extract)) or
        (any of ($gnome*, $kde*) and $dbus and $secret)
}

// ============================================================================
// Credential Files
// ============================================================================

rule Linux_Cred_Config_Files {
    meta:
        description = "Detects access to sensitive credential files"
        author = "YARA-EDR"
        severity = "medium"
        category = "credential_access"
    strings:
        $file1 = ".netrc" ascii
        $file2 = ".pgpass" ascii
        $file3 = ".my.cnf" ascii
        $file4 = ".aws/credentials" ascii
        $file5 = ".docker/config.json" ascii
        $file6 = ".kube/config" ascii
        $file7 = ".git-credentials" ascii
        $file8 = ".npmrc" ascii
        $file9 = ".pypirc" ascii
        $file10 = ".s3cfg" ascii
        $file11 = ".boto" ascii
        $file12 = ".env" ascii
        $read = "fopen" ascii
        $cat = "cat " ascii
    condition:
        (3 of ($file*)) or
        (any of ($file*) and any of ($read, $cat))
}

rule Linux_Cred_History_Files {
    meta:
        description = "Detects access to command history files"
        author = "YARA-EDR"
        severity = "medium"
        category = "credential_access"
    strings:
        $hist1 = ".bash_history" ascii
        $hist2 = ".zsh_history" ascii
        $hist3 = ".sh_history" ascii
        $hist4 = ".mysql_history" ascii
        $hist5 = ".psql_history" ascii
        $hist6 = ".python_history" ascii
        $hist7 = ".lesshst" ascii
        $hist8 = ".viminfo" ascii
        $grep1 = "grep" ascii
        $grep2 = "password" ascii nocase
        $grep3 = "passwd" ascii nocase
        $grep4 = "secret" ascii nocase
    condition:
        (2 of ($hist*) and any of ($grep*))
}

// ============================================================================
// Network Credential Sniffing
// ============================================================================

rule Linux_Cred_Network_Sniffer {
    meta:
        description = "Detects network credential sniffing tools"
        author = "YARA-EDR"
        severity = "critical"
        category = "credential_sniffing"
    strings:
        $pcap1 = "pcap_open" ascii
        $pcap2 = "pcap_loop" ascii
        $pcap3 = "pcap_next" ascii
        $raw1 = "SOCK_RAW" ascii
        $raw2 = "ETH_P_ALL" ascii
        $proto1 = "ftp" ascii nocase
        $proto2 = "telnet" ascii nocase
        $proto3 = "pop3" ascii nocase
        $proto4 = "imap" ascii nocase
        $proto5 = "smtp" ascii nocase
        $proto6 = "http" ascii nocase
        $cred1 = "USER" ascii
        $cred2 = "PASS" ascii
        $cred3 = "AUTH" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($pcap*) and any of ($proto*) and any of ($cred*)) or
        (all of ($raw*) and any of ($cred*))
}

rule Linux_Cred_MITM_Tool {
    meta:
        description = "Detects MITM attack tools"
        author = "YARA-EDR"
        severity = "critical"
        category = "credential_sniffing"
    strings:
        $tool1 = "ettercap" ascii nocase
        $tool2 = "bettercap" ascii nocase
        $tool3 = "arpspoof" ascii nocase
        $tool4 = "mitmproxy" ascii nocase
        $tool5 = "sslstrip" ascii nocase
        $tool6 = "responder" ascii nocase
        $arp1 = "arp" ascii
        $arp2 = "ARP_OP" ascii
        $arp3 = "ARPOP_REPLY" ascii
        $ssl1 = "ssl" ascii
        $ssl2 = "certificate" ascii nocase
    condition:
        any of ($tool*) or
        (2 of ($arp*) and any of ($ssl*))
}

// ============================================================================
// PAM Backdoor
// ============================================================================

rule Linux_Cred_PAM_Backdoor {
    meta:
        description = "Detects PAM module backdoors"
        author = "YARA-EDR"
        severity = "critical"
        category = "backdoor"
    strings:
        $pam1 = "pam_" ascii
        $pam2 = "/lib/security/" ascii
        $pam3 = "/lib64/security/" ascii
        $pam4 = "pam_sm_authenticate" ascii
        $pam5 = "PAM_SUCCESS" ascii
        $pam6 = "pam_unix.so" ascii
        $backdoor1 = "magic" ascii nocase
        $backdoor2 = "skeleton" ascii nocase
        $backdoor3 = "master" ascii nocase
        $log1 = "fopen" ascii
        $log2 = "/tmp/" ascii
        $log3 = "/var/log/" ascii
    condition:
        uint32(0) == 0x464c457f and
        (any of ($pam*) and any of ($backdoor*)) or
        ($pam4 and $pam5 and any of ($log*))
}

// ============================================================================
// Cloud Credential Theft
// ============================================================================

rule Linux_Cred_Cloud_Keys {
    meta:
        description = "Detects cloud credential theft"
        author = "YARA-EDR"
        severity = "critical"
        category = "credential_theft"
    strings:
        $aws1 = "AWS_ACCESS_KEY_ID" ascii
        $aws2 = "AWS_SECRET_ACCESS_KEY" ascii
        $aws3 = "aws_access_key_id" ascii
        $aws4 = "aws_secret_access_key" ascii
        $aws5 = ".aws/credentials" ascii
        $gcp1 = "GOOGLE_APPLICATION_CREDENTIALS" ascii
        $gcp2 = "type.*service_account" ascii
        $gcp3 = "private_key" ascii
        $azure1 = "AZURE_" ascii
        $azure2 = "azure.json" ascii
        $key_pattern = /[A-Z0-9]{20}/ ascii
        $exfil = "curl" ascii
    condition:
        (2 of ($aws*)) or
        (2 of ($gcp*)) or
        (any of ($azure*) and any of ($exfil, $key_pattern))
}

// ============================================================================
// Database Credential Access
// ============================================================================

rule Linux_Cred_Database_Access {
    meta:
        description = "Detects database credential access"
        author = "YARA-EDR"
        severity = "high"
        category = "credential_access"
    strings:
        $mysql1 = ".my.cnf" ascii
        $mysql2 = "mysql_config_editor" ascii
        $mysql3 = ".mylogin.cnf" ascii
        $pg1 = ".pgpass" ascii
        $pg2 = "PGPASSWORD" ascii
        $pg3 = "pg_hba.conf" ascii
        $mongo1 = ".dbshell" ascii
        $mongo2 = "mongod.conf" ascii
        $redis1 = "redis.conf" ascii
        $redis2 = "requirepass" ascii
        $read = "fopen" ascii
        $decrypt = "decrypt" ascii nocase
    condition:
        (any of ($mysql*, $pg*, $mongo*, $redis*) and any of ($read, $decrypt))
}
