# YARA-EDR Usage Guide

## Table of Contents

- [Quick Reference](#quick-reference)
- [Scanning Operations](#scanning-operations)
- [Daemon Mode](#daemon-mode)
- [Quarantine Management](#quarantine-management)
- [Alert Handling](#alert-handling)
- [Performance Tuning](#performance-tuning)

---

## Quick Reference

```bash
# Scan files
yara-edr scan /path/to/file
yara-edr scan /path/to/directory

# Scan process
yara-edr scan-process <PID>

# Daemon operations
sudo yara-edr start              # Start daemon
sudo yara-edr stop               # Stop daemon
yara-edr status                  # Check status

# Quarantine
yara-edr quarantine list         # List quarantined
yara-edr quarantine restore <id> # Restore file
yara-edr quarantine delete <id>  # Delete file

# Validation
yara-edr validate                # Check config/rules
```

---

## Scanning Operations

### File Scanning

Scan individual files or directories for threats:

```bash
# Single file
yara-edr scan /home/user/download.bin

# Multiple files
yara-edr scan file1.exe file2.sh file3.elf

# Directory (recursive)
yara-edr scan /var/www/html

# With verbose output
yara-edr -v scan /tmp/suspicious
```

#### Output Example

```
Scanning: "/tmp/suspicious/malware.elf"

[DETECTION] /tmp/suspicious/malware.elf
  Rule: Linux_Backdoor_Reverse_Shell
    description: Detects reverse shell patterns
    severity: high
    category: backdoor
  MD5: a1b2c3d4e5f6g7h8i9j0...
  SHA256: 1234567890abcdef...

=== Scan Complete ===
Files scanned: 15
Detections: 1
Duration: 0.52s
```

### Process Scanning

Scan running process memory:

```bash
# Scan by PID
sudo yara-edr scan-process 1234

# Scan current shell
yara-edr scan-process $$

# Find and scan suspicious process
ps aux | grep suspicious
sudo yara-edr scan-process <PID>
```

#### Output Example

```
Scanning process: PID 1234
  Name: cryptominer
  Path: /tmp/.hidden/xmrig
  User: www-data
  Memory Regions: 47

[DETECTION] Process 1234
  Rule: Linux_Cryptominer_Xmrig
    description: Detects XMRig miner
    severity: medium
  Matched in: heap (0x7f8a00000000)

Recommendation: Terminate process and investigate origin
```

### Scan Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Detailed output |
| `-c, --config` | Custom config file |
| `--timeout` | Scan timeout (seconds) |
| `--no-follow` | Don't follow symlinks |

---

## Daemon Mode

### Starting the Daemon

```bash
# Start in background
sudo yara-edr start

# Start in foreground (for debugging)
sudo yara-edr start --foreground

# With custom config
sudo yara-edr -c /path/to/config.toml start
```

### Monitoring

```bash
# Check status
yara-edr status

# View real-time logs
sudo tail -f /var/log/yara-edr/edr.log

# View alerts
sudo tail -f /var/log/yara-edr/alerts.json | jq .
```

### Stopping the Daemon

```bash
# Graceful stop
sudo yara-edr stop

# Force stop (if unresponsive)
sudo kill -9 $(cat /var/run/yara-edr.pid)
```

### Reloading Rules

Send SIGHUP to reload rules without restart:

```bash
sudo kill -HUP $(cat /var/run/yara-edr.pid)
```

---

## Quarantine Management

### List Quarantined Files

```bash
yara-edr quarantine list
```

Output:

```
ID                                    Original Path                  Date                 Rule
────────────────────────────────────────────────────────────────────────────────────────────────
a1b2c3d4-e5f6-7890-abcd-ef1234567890  /tmp/malware.elf              2024-01-15 14:32:01  Linux_Backdoor
b2c3d4e5-f6a7-8901-bcde-f12345678901  /var/www/shell.php            2024-01-15 15:10:45  PHP_Webshell
```

### View Quarantine Statistics

```bash
yara-edr quarantine stats
```

Output:

```
Quarantine Statistics
─────────────────────
Total files: 12
Total size: 4.2 MB
Oldest: 2024-01-10
Newest: 2024-01-15

By Severity:
  critical: 3
  high: 5
  medium: 4
```

### Restore a File

```bash
# Restore to original location
yara-edr quarantine restore a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Restore to different location
yara-edr quarantine restore a1b2c3d4 --dest /tmp/recovered/
```

### Delete Quarantined Files

```bash
# Delete single file
yara-edr quarantine delete a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Delete all (use with caution)
yara-edr quarantine delete --all
```

---

## Alert Handling

### Alert Format

Alerts are stored as JSON in `/var/log/yara-edr/alerts.json`:

```json
{
  "timestamp": "2024-01-15T14:32:01.123Z",
  "event_type": "detection",
  "file_path": "/tmp/malware.elf",
  "rule_name": "Linux_Backdoor_Reverse_Shell",
  "rule_meta": {
    "description": "Detects reverse shell patterns",
    "severity": "high",
    "category": "backdoor"
  },
  "file_hash": {
    "md5": "a1b2c3d4e5f6...",
    "sha256": "1234567890ab..."
  },
  "action_taken": "quarantined"
}
```

### Parsing Alerts

```bash
# View recent alerts
tail -10 /var/log/yara-edr/alerts.json | jq .

# Filter by severity
cat /var/log/yara-edr/alerts.json | jq 'select(.rule_meta.severity == "critical")'

# Count by rule
cat /var/log/yara-edr/alerts.json | jq -r '.rule_name' | sort | uniq -c | sort -rn
```

### Alert Integration

#### Syslog

```toml
[alerts]
output = "syslog"
```

#### Webhook

```bash
# Example: Send alerts to Slack
tail -f /var/log/yara-edr/alerts.json | while read line; do
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\": \"$line\"}" \
    https://hooks.slack.com/services/YOUR/WEBHOOK/URL
done
```

---

## Performance Tuning

### Reduce Resource Usage

1. **Limit watched paths**:
```toml
[file_monitor]
watch_paths = ["/home", "/tmp"]  # Only critical paths
```

2. **Increase debounce time**:
```toml
[file_monitor]
debounce_ms = 1000  # Wait 1 second between events
```

3. **Limit file size**:
```toml
[file_monitor]
max_file_size = 52428800  # 50 MB max
```

4. **Reduce rule count**:
```toml
[rules]
paths = ["./rules/linux_apt.yar", "./rules/linux_privesc.yar"]
```

### Optimize for Large Directories

```toml
[file_monitor]
exclude_patterns = [
  "*.log",
  "*.tmp",
  "/proc/*",
  "/sys/*",
  "/dev/*",
  "node_modules/*",
  ".git/*"
]
```

### Increase inotify Limits

```bash
# Temporary
sudo sysctl fs.inotify.max_user_watches=524288

# Permanent
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Common Workflows

### Incident Response

```bash
# 1. Check for active threats
sudo yara-edr scan / --timeout 300

# 2. Scan suspicious processes
for pid in $(ps aux | grep -E 'crypto|miner|shell' | awk '{print $2}'); do
  sudo yara-edr scan-process $pid
done

# 3. Review recent alerts
cat /var/log/yara-edr/alerts.json | jq 'select(.timestamp > "2024-01-15")'

# 4. Check quarantine
yara-edr quarantine list
```

### Scheduled Scanning

Add to crontab:

```bash
# Daily full scan at 2 AM
0 2 * * * /usr/local/bin/yara-edr scan / >> /var/log/yara-edr/daily-scan.log 2>&1

# Hourly /tmp scan
0 * * * * /usr/local/bin/yara-edr scan /tmp /var/tmp >> /var/log/yara-edr/hourly-scan.log 2>&1
```

### Rule Testing

```bash
# Create test file
echo 'test_malware_string' > /tmp/test.txt

# Create test rule
cat > /tmp/test.yar << 'EOF'
rule Test_Rule {
    strings:
        $s = "test_malware_string"
    condition:
        $s
}
EOF

# Test
yara-edr -c /dev/null scan /tmp/test.txt
```
