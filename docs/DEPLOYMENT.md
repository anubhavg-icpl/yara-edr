# YARA-EDR Deployment Guide

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Production Deployment](#production-deployment)
- [High Availability Setup](#high-availability-setup)
- [Containerized Deployment](#containerized-deployment)

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Linux (kernel 2.6.13+) |
| Architecture | x86_64 |
| RAM | 512 MB |
| Disk | 50 MB + rules storage |
| Dependencies | libyara.so (YARA 4.x) |

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Ubuntu 22.04 LTS / RHEL 8+ |
| RAM | 2 GB |
| Disk | 500 MB |
| CPU | 2+ cores |

---

## Installation Methods

### Method 1: Binary Release (Recommended)

```bash
# Download latest release
wget https://github.com/anubhavg-icpl/yara-edr/releases/latest/download/yara-edr-linux-amd64.tar.gz

# Verify checksum
wget https://github.com/anubhavg-icpl/yara-edr/releases/latest/download/yara-edr-linux-amd64.tar.gz.sha256
sha256sum -c yara-edr-linux-amd64.tar.gz.sha256

# Extract
tar -xzf yara-edr-linux-amd64.tar.gz
cd yara-edr-release

# Install
sudo mv yara-edr /usr/local/bin/
sudo mkdir -p /etc/yara-edr
sudo cp -r rules /etc/yara-edr/
sudo cp config/config.toml /etc/yara-edr/
```

### Method 2: Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install YARA development files
sudo apt install libyara-dev  # Debian/Ubuntu
sudo yum install yara-devel   # RHEL/CentOS

# Clone and build
git clone https://github.com/anubhavg-icpl/yara-edr.git
cd yara-edr
cargo build --release

# Install
sudo cp target/release/yara-edr /usr/local/bin/
```

### Method 3: Package Manager (Coming Soon)

```bash
# Arch Linux (AUR)
yay -S yara-edr

# Ubuntu/Debian (PPA)
sudo add-apt-repository ppa:yara-edr/stable
sudo apt update && sudo apt install yara-edr
```

---

## Production Deployment

### Directory Structure

```
/etc/yara-edr/
├── config.toml          # Main configuration
├── rules/               # Detection rules
│   ├── elastic_linux.yar
│   ├── linux_apt.yar
│   └── ...
└── custom/              # Custom rules (optional)

/var/lib/yara-edr/
├── quarantine/          # Quarantined files
└── state/               # Runtime state

/var/log/yara-edr/
├── edr.log              # Application logs
└── alerts.json          # Detection alerts
```

### Setup Script

```bash
#!/bin/bash
# setup-yara-edr.sh

set -e

# Create directories
sudo mkdir -p /etc/yara-edr/rules
sudo mkdir -p /etc/yara-edr/custom
sudo mkdir -p /var/lib/yara-edr/quarantine
sudo mkdir -p /var/lib/yara-edr/state
sudo mkdir -p /var/log/yara-edr

# Set permissions
sudo chmod 750 /etc/yara-edr
sudo chmod 750 /var/lib/yara-edr/quarantine
sudo chmod 755 /var/log/yara-edr

# Create dedicated user (optional)
sudo useradd -r -s /bin/false yara-edr || true
sudo chown -R yara-edr:yara-edr /var/lib/yara-edr
sudo chown -R yara-edr:yara-edr /var/log/yara-edr

echo "Setup complete"
```

### Systemd Service

Create `/etc/systemd/system/yara-edr.service`:

```ini
[Unit]
Description=YARA-EDR Endpoint Detection and Response
Documentation=https://github.com/anubhavg-icpl/yara-edr
After=network.target

[Service]
Type=forking
User=root
ExecStart=/usr/local/bin/yara-edr start
ExecStop=/usr/local/bin/yara-edr stop
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/yara-edr.pid
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security hardening
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/yara-edr /var/log/yara-edr /var/run
NoNewPrivileges=false
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable yara-edr
sudo systemctl start yara-edr
sudo systemctl status yara-edr
```

---

## High Availability Setup

### Multi-Node Deployment

For enterprise environments, deploy YARA-EDR on multiple nodes with centralized logging:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Node 1    │     │   Node 2    │     │   Node 3    │
│  yara-edr   │     │  yara-edr   │     │  yara-edr   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌──────┴──────┐
                    │   Syslog    │
                    │   Server    │
                    └─────────────┘
```

### Syslog Configuration

Update `/etc/yara-edr/config.toml`:

```toml
[alerts]
output = "syslog"
syslog_facility = "local0"
syslog_level = "info"
```

---

## Containerized Deployment

### Docker

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libyara-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/yara-edr

COPY yara-edr /usr/local/bin/
COPY rules/ /etc/yara-edr/rules/
COPY config.toml /etc/yara-edr/

RUN mkdir -p /var/lib/yara-edr/quarantine /var/log/yara-edr

ENTRYPOINT ["yara-edr"]
CMD ["start", "--foreground"]
```

### Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: yara-edr
  namespace: security
spec:
  selector:
    matchLabels:
      app: yara-edr
  template:
    metadata:
      labels:
        app: yara-edr
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: yara-edr
        image: yara-edr:v1.1.0
        securityContext:
          privileged: true
        volumeMounts:
        - name: host-root
          mountPath: /host
          readOnly: true
        - name: rules
          mountPath: /etc/yara-edr/rules
      volumes:
      - name: host-root
        hostPath:
          path: /
      - name: rules
        configMap:
          name: yara-edr-rules
```

---

## Post-Installation

### Validate Installation

```bash
# Check version
yara-edr --version

# Validate configuration and rules
yara-edr validate

# Test scan
yara-edr scan /tmp
```

### Verify Service Status

```bash
# Check service
sudo systemctl status yara-edr

# View logs
sudo journalctl -u yara-edr -f

# Check alerts
sudo tail -f /var/log/yara-edr/alerts.json
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| YARA library not found | `export LD_LIBRARY_PATH=/usr/local/lib` |
| Permission denied | Run with `sudo` or check file permissions |
| Too many inotify watches | Increase `fs.inotify.max_user_watches` |
| High memory usage | Reduce watched paths or rule count |

### Debug Mode

```bash
RUST_LOG=debug yara-edr start --foreground
```
