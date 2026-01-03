/*
    Linux Fileless Malware Detection Rules
    Detects memory-only attacks, script-based malware, and living-off-the-land techniques
    Author: YARA-EDR
*/

import "elf"

// ============================================================================
// Memory-Only Execution
// ============================================================================

rule Linux_Fileless_Memfd_Create {
    meta:
        description = "Detects memfd_create for anonymous file execution"
        author = "YARA-EDR"
        severity = "high"
        category = "fileless"
    strings:
        $memfd1 = "memfd_create" ascii
        $memfd2 = "MFD_CLOEXEC" ascii
        $memfd3 = "MFD_ALLOW_SEALING" ascii
        $exec1 = "fexecve" ascii
        $exec2 = "execveat" ascii
        $proc = "/proc/self/fd/" ascii
        $shm = "/dev/shm" ascii
    condition:
        uint32(0) == 0x464c457f and
        ($memfd1 and any of ($exec*, $proc)) or
        (all of ($memfd*) and $shm)
}

rule Linux_Fileless_SHM_Exec {
    meta:
        description = "Detects execution from /dev/shm (tmpfs)"
        author = "YARA-EDR"
        severity = "high"
        category = "fileless"
    strings:
        $shm1 = "/dev/shm/" ascii
        $shm2 = "/run/shm/" ascii
        $ex1 = "execve" ascii
        $ex2 = "chmod +x" ascii
        $ex3 = "system(" ascii
        $write = "fwrite" ascii
        $create = "fopen" ascii
    condition:
        any of ($shm*) and any of ($ex*) and any of ($write, $create)
}

rule Linux_Fileless_Proc_Self_Mem {
    meta:
        description = "Detects process memory manipulation for fileless execution"
        author = "YARA-EDR"
        severity = "high"
        category = "fileless"
    strings:
        $mem1 = "/proc/self/mem" ascii
        $mem2 = "/proc/%d/mem" ascii
        $maps = "/proc/self/maps" ascii
        $seek = "lseek" ascii
        $write = "write" ascii
        $mprotect = "mprotect" ascii
        // hex patterns removed
        // hex patterns removed
    condition:
        uint32(0) == 0x464c457f and
        (any of ($mem*) and $maps and $mprotect) or
        (any of ($mem*) and $seek and $write)
}

// ============================================================================
// Script-Based Attacks
// ============================================================================

rule Linux_Fileless_Bash_Pipe_Exec {
    meta:
        description = "Detects bash pipe execution (curl | bash pattern)"
        author = "YARA-EDR"
        severity = "high"
        category = "fileless"
    strings:
        $curl_bash1 = "curl" ascii
        $curl_bash2 = "wget" ascii
        $pipe1 = "| bash" ascii
        $pipe2 = "| sh" ascii
        $pipe3 = "|bash" ascii
        $pipe4 = "|sh" ascii
        $pipe5 = "| /bin/bash" ascii
        $pipe6 = "| /bin/sh" ascii
        $eval1 = "eval $(" ascii
        $b64 = "base64 -d" ascii
    condition:
        (any of ($curl_bash*) and any of ($pipe*)) or
        (any of ($eval*) and any of ($curl_bash*)) or
        (any of ($curl_bash*) and $b64 and any of ($pipe*))
}

rule Linux_Fileless_Python_Exec {
    meta:
        description = "Detects Python-based fileless execution"
        author = "YARA-EDR"
        severity = "high"
        category = "fileless"
    strings:
        $py1 = "python -c" ascii
        $py2 = "python3 -c" ascii
        $py3 = /exec\s*\(/ ascii
        $py4 = /eval\s*\(/ ascii
        $import1 = "import socket" ascii
        $import2 = "import subprocess" ascii
        $import3 = "import os" ascii
        $import4 = "__import__" ascii
        $b64 = "base64.b64decode" ascii
        $marshal = "marshal.loads" ascii
    condition:
        (any of ($py1, $py2) and 2 of ($import*)) or
        ($b64 and any of ($py3, $py4)) or
        ($marshal and any of ($py3, $py4))
}

rule Linux_Fileless_Perl_Exec {
    meta:
        description = "Detects Perl-based fileless execution"
        author = "YARA-EDR"
        severity = "high"
        category = "fileless"
    strings:
        $perl1 = "perl -e" ascii
        $perl2 = "perl -M" ascii
        $socket = "use Socket" ascii
        $io = "use IO::Socket" ascii
        // regex removed
        $pack = "pack(" ascii
    condition:
        (any of ($perl*) and any of ($socket, $io)) or
        ($pack and any of ($socket, $io))
}

// ============================================================================
// Living Off The Land Binaries (LOLBins)
// ============================================================================

rule Linux_LOTL_GTFOBins_General {
    meta:
        description = "Detects GTFOBins abuse for command execution"
        author = "YARA-EDR"
        severity = "high"
        category = "lotl"
    strings:
        $awk = "awk '{print}'" ascii
        $base64 = "base64 -d" ascii
        $bash = "bash -c" ascii
        $busybox = "busybox" ascii
        $vim = "vim -c" ascii
        $vi = "vi -c" ascii
        $curl_out = "curl -o" ascii
        $wget_exec = "wget -q -O-" ascii
        $nc_e = "nc -e" ascii
        $ncat = "ncat -e" ascii
        $socat = "socat" ascii
        $gdb_shell = "gdb -nx -ex" ascii
        $lua = "lua -e" ascii
        $node = "node -e" ascii
        $php = "php -r" ascii
        $env = "env /bin/sh" ascii
        $find_exec = "find . -exec" ascii
        $xargs = "xargs -a" ascii
    condition:
        3 of them
}

rule Linux_LOTL_Reverse_Shell {
    meta:
        description = "Detects LOLBin reverse shell techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "lotl"
    strings:
        $bash_tcp = "/dev/tcp/" ascii
        $bash_udp = "/dev/udp/" ascii
        $bash_i = "bash -i" ascii
        $py_sock = "socket.socket" ascii
        $py_pty = "pty.spawn" ascii
        $nc1 = "nc -e /bin" ascii
        $nc2 = "nc -c /bin" ascii
        $perl_sock = "use Socket" ascii
        $php_sock = "fsockopen" ascii
        $ruby_sock = "TCPSocket.new" ascii
        $socat_pty = "socat exec:'bash -li'" ascii
        $socat_tcp = "socat tcp:" ascii
    condition:
        2 of them
}

rule Linux_LOTL_Data_Exfil {
    meta:
        description = "Detects data exfiltration via LOLBins"
        author = "YARA-EDR"
        severity = "high"
        category = "lotl"
    strings:
        $dns1 = "nslookup" ascii
        $dns2 = "dig" ascii
        $dns3 = "host" ascii
        $curl_post = "curl -X POST" ascii
        $curl_data = "curl -d" ascii
        $wget_post = "wget --post-data" ascii
        $b64 = "base64" ascii
        $xxd = "xxd" ascii
        // removed unused nc_send
        $openssl = "openssl s_client" ascii
        $tar_pipe = "tar -c" ascii
        $zip_pipe = "zip -" ascii
    condition:
        (any of ($dns*) and $b64) or
        (any of ($curl_post, $curl_data, $wget_post) and any of ($b64, $tar_pipe, $zip_pipe)) or
        ($openssl and any of ($b64, $xxd))
}

// ============================================================================
// In-Memory Shellcode Execution
// ============================================================================

rule Linux_Fileless_Shellcode_Loader {
    meta:
        description = "Detects in-memory shellcode loader patterns"
        author = "YARA-EDR"
        severity = "critical"
        category = "shellcode"
    strings:
        $mmap1 = "mmap" ascii
        $mmap2 = "PROT_EXEC" ascii
        $mmap3 = "PROT_READ" ascii
        $mmap4 = "PROT_WRITE" ascii
        $mprotect = "mprotect" ascii
        $memcpy = "memcpy" ascii
        $call1 = { FF D0 }
        $call2 = { FF D3 }
        $call3 = { FF E0 }
        $jmp = { 41 FF E4 }
    condition:
        uint32(0) == 0x464c457f and
        ($mmap1 and $mmap2 and $memcpy and any of ($call*, $jmp)) or
        ($mprotect and $memcpy and 2 of ($mmap*))
}

rule Linux_Fileless_ELF_Memory_Load {
    meta:
        description = "Detects ELF loading into memory without file"
        author = "YARA-EDR"
        severity = "critical"
        category = "fileless"
    strings:
        // removed elf magic
        $dlopen = "dlopen" ascii
        $dlsym = "dlsym" ascii
        $mmap = "mmap" ascii
        $shm = "/dev/shm" ascii
        $memfd = "memfd_create" ascii
        $proc_fd = "/proc/self/fd" ascii
    condition:
        uint32(0) == 0x464c457f and
        (($dlopen or $dlsym) and ($shm or $memfd or $proc_fd)) or
        ($mmap and ($memfd or $shm) and any of ($dlopen, $dlsym))
}

// ============================================================================
// Process Hollowing/Injection
// ============================================================================

rule Linux_Fileless_Process_Hollowing {
    meta:
        description = "Detects process hollowing techniques on Linux"
        author = "YARA-EDR"
        severity = "critical"
        category = "injection"
    strings:
        $ptrace1 = "ptrace" ascii
        $ptrace2 = "PTRACE_ATTACH" ascii
        $ptrace3 = "PTRACE_POKETEXT" ascii
        $ptrace4 = "PTRACE_POKEDATA" ascii
        $ptrace5 = "PTRACE_SETREGS" ascii
        $ptrace6 = "PTRACE_CONT" ascii
        $mem = "/proc/%d/mem" ascii
        $maps = "/proc/%d/maps" ascii
        $wait = "waitpid" ascii
    condition:
        uint32(0) == 0x464c457f and
        ($ptrace1 and 2 of ($ptrace2, $ptrace3, $ptrace4, $ptrace5, $ptrace6)) or
        (any of ($mem, $maps) and $ptrace1 and $wait)
}

rule Linux_Fileless_LD_Preload_Injection {
    meta:
        description = "Detects LD_PRELOAD injection techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "injection"
    strings:
        $ld_preload = "LD_PRELOAD" ascii
        // removed ld_lib
        $ld_so = "/etc/ld.so.preload" ascii
        $dlopen = "dlopen" ascii
        $dlsym = "dlsym" ascii
        $rtld_next = "RTLD_NEXT" ascii
        // removed rtld_lazy
        $ptrace = "ptrace" ascii
    condition:
        uint32(0) == 0x464c457f and
        (($ld_preload or $ld_so) and ($dlopen or $dlsym)) or
        ($rtld_next and 2 of ($dlopen, $dlsym, $ptrace))
}

// ============================================================================
// Cryptominer Fileless Execution
// ============================================================================

rule Linux_Fileless_Miner {
    meta:
        description = "Detects fileless cryptocurrency miner execution"
        author = "YARA-EDR"
        severity = "high"
        category = "cryptominer"
    strings:
        $curl = "curl" ascii
        $wget = "wget" ascii
        $pipe = "|" ascii
        $bash = "bash" ascii
        $sh = "sh" ascii
        $stratum = "stratum" ascii
        $pool = "pool" ascii
        $xmr = "xmr" ascii nocase
        $randomx = "randomx" ascii nocase
        $miner = "miner" ascii nocase
        $shm = "/dev/shm" ascii
        $tmp = "/tmp" ascii
    condition:
        (any of ($curl, $wget) and $pipe and any of ($bash, $sh) and any of ($stratum, $pool, $xmr)) or
        (any of ($shm, $tmp) and any of ($miner, $randomx) and any of ($stratum, $pool))
}

// ============================================================================
// eBPF-based Fileless Attacks
// ============================================================================

rule Linux_Fileless_eBPF_Rootkit {
    meta:
        description = "Detects eBPF-based fileless rootkit techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "rootkit"
    strings:
        $bpf1 = "bpf(" ascii
        $bpf2 = "BPF_PROG_LOAD" ascii
        $bpf3 = "BPF_MAP_" ascii
        $bpf4 = "libbpf" ascii
        $bpf5 = "bpf_probe" ascii
        $type1 = "BPF_PROG_TYPE_KPROBE" ascii
        $type2 = "BPF_PROG_TYPE_TRACEPOINT" ascii
        $type3 = "BPF_PROG_TYPE_RAW_TRACEPOINT" ascii
        $hook = "sys_enter" ascii
        $hide = "getdents" ascii
    condition:
        uint32(0) == 0x464c457f and
        (2 of ($bpf*) and any of ($type*)) or
        (any of ($bpf*) and $hook and $hide)
}

// ============================================================================
// Environment Variable Abuse
// ============================================================================

rule Linux_Fileless_Env_Abuse {
    meta:
        description = "Detects environment variable abuse for code execution"
        author = "YARA-EDR"
        severity = "high"
        category = "fileless"
    strings:
        $env1 = "LD_PRELOAD" ascii
        $env2 = "LD_LIBRARY_PATH" ascii
        $env3 = "LD_AUDIT" ascii
        $env4 = "LD_DEBUG" ascii
        $env5 = "BASH_ENV" ascii
        $env6 = "BASH_FUNC_" ascii
        $env7 = "PROMPT_COMMAND" ascii
        $shell_shock = "() {" ascii
        $export = "export" ascii
    condition:
        (3 of ($env*) and $export) or
        ($shell_shock and any of ($env*))
}
