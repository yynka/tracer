████████╗██████╗  █████╗  ██████╗███████╗██████╗ 
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗
   ██║   ██████╔╝███████║██║     █████╗  ██████╔╝
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══██╗
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝
```

**Complete Usage Guide & Technical Reference**

## Table of Contents

▸ [Quick Start](#quick-start)  
▸ [Command Reference](#command-reference)  
▸ [Discovery Mode](#discovery-mode)  
▸ [Monitor Mode](#monitor-mode)  
▸ [Analysis Mode](#analysis-mode)  
▸ [Global Options](#global-options)  
▸ [Advanced Usage](#advanced-usage)  
▸ [Database Schema](#database-schema)  
▸ [Troubleshooting](#troubleshooting)  
▸ [Technical Details](#technical-details)  
▸ [Best Practices](#best-practices)  

---

## Quick Start

### 1. Basic Network Discovery
```bash
# Quick device scan
python3 main.py discover --fast

# Detailed scan with summary
python3 main.py discover --summary

# Authenticated scan for enhanced profiling
python3 main.py discover --username admin --password secret --summary
```

### 2. Traffic Monitoring
```bash
# Start packet capture (requires sudo)
sudo python3 main.py monitor

# Monitor specific interface
sudo python3 main.py monitor --interface en0

# Background monitoring with debug
sudo python3 main.py monitor --debug &
```

### 3. Data Analysis
```bash
# Basic network analysis
python3 main.py analyze

# Security-focused analysis with export
python3 main.py analyze --security --export

# Complete workflow analysis
python3 main.py analyze --security --export
```

### 4. Complete Workflow
```bash
# Step 1: Discover devices
python3 main.py discover --fast --summary

# Step 2: Monitor traffic (background)
sudo python3 main.py monitor &

# Step 3: After monitoring, analyze results
python3 main.py analyze --security --export
```

---

## Command Reference

### Universal Command Structure

```bash
python3 main.py <mode> [options]
```

### Available Modes

| Mode | Description | Requires Root |
|------|-------------|---------------|
| `discover` | Network device discovery and profiling | No |
| `monitor` | Real-time packet capture and analysis | Yes |
| `analyze` | Data analysis and security assessment | No |

### Global Options

All modes support these global options:

| Option | Description | Default |
|--------|-------------|---------|
| `--log-path PATH` | Custom directory for logs and database | `./logs` |
| `--debug` | Enable verbose debug logging | Disabled |
| `--help` | Show help message and exit | - |

---

## Discovery Mode

### Purpose
Network device discovery identifies all active devices on your network and creates detailed profiles including hostname, platform, vendor, and accessibility status.

### Basic Syntax
```bash
python3 main.py discover [options]
```

### Discovery Options

| Option | Description | Impact |
|--------|-------------|--------|
| `--username USER` | Username for device authentication | Enables detailed OS profiling |
| `--password PASS` | Password for device authentication | Required with username |
| `--fast` | Quick scan mode with fewer checks | Faster execution, less detail |
| `--summary` | Display detailed device summary | Shows comprehensive results |

### Discovery Examples

#### Basic Discovery
```bash
# Minimal device discovery
python3 main.py discover

# Expected output:
# [*] Starting network discovery...
# [+] Found active host: 192.168.1.1 (router.local)
# [+] Found active host: 192.168.1.100 (MacBook-Pro.local)
# [+] Found 12 active devices
```

#### Fast Discovery with Summary
```bash
# Quick scan with detailed output
python3 main.py discover --fast --summary

# Expected output:
# ================================================================================
# DEVICE DISCOVERY SUMMARY
# ================================================================================
# 
# [1] 192.168.1.1
#     Hostname: router.local
#     Platform: Unknown
#     Vendor: Netgear
#     Accessible: Yes
```

#### Authenticated Discovery
```bash
# Enhanced profiling with credentials
python3 main.py discover --username admin --password secret --summary

# Additional information gathered:
# - OS version details
# - Running services
# - Shared resources
# - System information
```

### Discovery Process

1. **Network Range Detection** - Automatically detects local network subnets
2. **ARP Table Scan** - Parses system ARP table for known devices
3. **Ping Sweep** - Multithreaded ping scan across network range
4. **Port Scanning** - Uses nmap for service detection
5. **Device Profiling** - Creates comprehensive device profiles
6. **Database Storage** - Saves profiles to SQLite database

### Discovery Output Files

- `logs/network_monitor.db` - Device profiles in database
- `logs/[IP_ADDRESS].json` - Individual device profile files
- `logs/network_monitor.log` - Discovery debug log

---

## Monitor Mode

### Purpose
Real-time packet capture monitors all network traffic, analyzes communication flows, and correlates traffic with discovered devices.

### Basic Syntax
```bash
sudo python3 main.py monitor [options]
```

### Monitor Options

| Option | Description | Impact |
|--------|-------------|--------|
| `--interface IFACE` | Specific network interface to monitor | Defaults to auto-detection |

### Monitor Examples

#### Basic Monitoring
```bash
# Auto-detect interface and start capture
sudo python3 main.py monitor

# Expected output:
# [*] Starting packet capture on interface: en0
# [*] Local networks: ['192.168.1.0/24']
# [*] Press Ctrl+C to stop capture
```

#### Interface-Specific Monitoring
```bash
# Monitor specific network interface
sudo python3 main.py monitor --interface eth0

# Useful when multiple interfaces are present
```

#### Background Monitoring
```bash
# Run monitoring in background
sudo python3 main.py monitor --debug &

# Monitor process ID for later management
MONITOR_PID=$!
```

### Monitor Process

1. **Network Interface Detection** - Identifies available network interfaces
2. **Local Network Mapping** - Determines local IP ranges and subnets
3. **Packet Capture** - Live capture of network packets using Scapy
4. **Protocol Analysis** - Dissects TCP, UDP, ICMP, and other protocols
5. **Flow Tracking** - Maintains connection state and flow statistics
6. **Device Correlation** - Links traffic to discovered device profiles
7. **Real-time Statistics** - Updates statistics every 30 seconds

### Monitor Output

#### Console Output
```bash
============================================================
PACKET CAPTURE STATISTICS - 14:35:22
============================================================
Active Flows: 42
Total Packets: 15,847
Total Bytes: 23,456,789 (22.37 MB)

Top 5 Active Devices:
  192.168.1.100   |   1,243 pkts |   2,456,789 bytes
  192.168.1.1     |     987 pkts |   1,234,567 bytes
```

#### Database Updates
- Flow statistics updated in real-time
- Device traffic counters maintained
- Packet events logged for analysis

### Traffic Classification

| Direction | Description | Example |
|-----------|-------------|---------|
| `inbound` | External → Local network | Internet → Your device |
| `outbound` | Local network → External | Your device → Internet |
| `internal` | Local ↔ Local communication | Device → Router |
| `transit` | Neither source nor destination is local | Routing traffic |

---

## Analysis Mode

### Purpose
Comprehensive analysis of discovered devices and captured traffic data, with security assessment and reporting capabilities.

### Basic Syntax
```bash
python3 main.py analyze [options]
```

### Analysis Options

| Option | Description | Output |
|--------|-------------|--------|
| `--security` | Focus on security analysis | Security concerns and recommendations |
| `--export` | Export analysis report to JSON | Timestamped report file |

### Analysis Examples

#### Basic Analysis
```bash
# Standard network analysis
python3 main.py analyze

# Expected output:
# NETWORK ANALYSIS
# ================================================================================
# Network Summary:
#   Device Profiles: 12
#   Devices with Traffic: 8
#   Total Traffic: 145.7 MB
```

#### Security Analysis
```bash
# Security-focused analysis
python3 main.py analyze --security

# Additional output:
# SECURITY ANALYSIS
# ================================================================================
# Security Concerns Found: 3
# 
# • High Outbound Traffic
#   Device: 192.168.1.100 (MacBook-Pro.local)
#   Details: 45.2 MB outbound vs 12.1 MB inbound
```

#### Export Analysis
```bash
# Generate exportable report
python3 main.py analyze --security --export

# Output:
# [+] Analysis report exported to: logs/network_analysis_20231201_143522.json
```

### Analysis Components

#### Device Analysis
- Traffic volume rankings
- Platform distribution
- Vendor analysis
- Accessibility assessment

#### Security Analysis
- High outbound traffic detection
- Unknown device identification
- Multi-protocol activity analysis
- Anomaly detection

#### Report Generation
- JSON export with full data
- Timestamped analysis snapshots
- Integration-ready format

---

## Global Options

### Log Path Configuration

```bash
# Custom log directory
python3 main.py discover --log-path /custom/path

# Creates:
# /custom/path/network_monitor.db
# /custom/path/network_monitor.log
# /custom/path/*.json
```

### Debug Logging

```bash
# Enable verbose debugging
python3 main.py discover --debug

# Additional output:
# DEBUG: Network interface detected: en0
# DEBUG: ARP entry found: 192.168.1.1 -> aa:bb:cc:dd:ee:ff
# DEBUG: Ping successful: 192.168.1.100
```

### Help System

```bash
# Main help
python3 main.py --help

# Mode-specific help
python3 main.py discover --help
python3 main.py monitor --help
python3 main.py analyze --help
```

---

## Advanced Usage

### Workflow Automation

#### Daily Monitoring Script
```bash
#!/bin/bash
# daily_monitor.sh

LOG_DIR="/var/log/tracer"
DATE=$(date +%Y%m%d)

# Activate virtual environment
source t/bin/activate

# Daily device discovery
python3 main.py discover --fast --summary \
  --log-path "$LOG_DIR" > "$LOG_DIR/discovery_$DATE.log"

# Monitor for 4 hours
timeout 14400 sudo python3 main.py monitor \
  --log-path "$LOG_DIR" --debug &

# Generate daily report
python3 main.py analyze --security --export \
  --log-path "$LOG_DIR"
```

#### Continuous Monitoring
```bash
#!/bin/bash
# continuous_monitor.sh

while true; do
    # Discover new devices every hour
    python3 main.py discover --fast
    
    # Start monitoring
    sudo python3 main.py monitor --debug &
    MONITOR_PID=$!
    
    # Monitor for 30 minutes
    sleep 1800
    
    # Stop monitoring and analyze
    kill $MONITOR_PID
    python3 main.py analyze --security --export
    
    # Wait before next cycle
    sleep 300
done
```

### Integration Examples

#### Cron Integration
```bash
# Add to crontab
0 */6 * * * cd /path/to/tracer && python3 main.py discover --fast
0 1 * * * cd /path/to/tracer && python3 main.py analyze --security --export
```

#### Log Analysis Integration
```bash
# Export for external analysis
python3 main.py analyze --export
jq '.device_profiles' logs/network_analysis_*.json > devices.json
```

---

## Database Schema

### Overview
Tracer uses SQLite for persistent storage with the following structure:

```sql
-- Database file: logs/network_monitor.db
```

### Tables

#### device_profiles
```sql
CREATE TABLE device_profiles (
    ip_address TEXT PRIMARY KEY,
    hostname TEXT,
    mac_address TEXT,
    vendor TEXT,
    computer_name TEXT,
    os_version TEXT,
    platform TEXT,
    is_accessible BOOLEAN,
    first_seen TEXT,
    last_seen TEXT,
    profile_data TEXT -- JSON blob
);
```

#### packet_flows
```sql
CREATE TABLE packet_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    packet_count INTEGER,
    total_bytes INTEGER,
    direction TEXT,
    first_seen TEXT,
    last_seen TEXT
);
```

#### device_stats
```sql
CREATE TABLE device_stats (
    ip_address TEXT PRIMARY KEY,
    hostname TEXT,
    total_bytes_in INTEGER,
    total_bytes_out INTEGER,
    total_packets_in INTEGER,
    total_packets_out INTEGER,
    protocols_used TEXT,
    first_seen TEXT,
    last_seen TEXT
);
```

### Database Queries

#### Top Traffic Devices
```sql
SELECT ip_address, hostname, 
       (total_bytes_in + total_bytes_out) as total_bytes
FROM device_stats 
ORDER BY total_bytes DESC 
LIMIT 10;
```

#### Security Analysis Query
```sql
SELECT ip_address, hostname, total_bytes_out, total_bytes_in
FROM device_stats 
WHERE total_bytes_out > (total_bytes_in * 2) 
  AND total_bytes_out > 50000000;  -- 50MB
```

---

## Troubleshooting

### Common Issues

#### Permission Denied (Monitor Mode)

**Symptoms:** "Permission denied" when starting monitor mode
**Cause:** Packet capture requires root privileges
**Solution:**
```bash
# Use sudo for monitor mode
sudo python3 main.py monitor

# Check current user
whoami

# Verify sudo access
sudo -v
```

#### No Network Interface Found

**Symptoms:** "No network interface found" error
**Cause:** Auto-detection failed or restricted permissions
**Solution:**
```bash
# List available interfaces
ifconfig  # macOS/Linux
ip addr show  # Linux

# Specify interface manually
sudo python3 main.py monitor --interface en0
```

#### No Devices Discovered

**Symptoms:** Discovery finds 0 devices
**Causes & Solutions:**

1. **Wrong Network Segment**
   ```bash
   # Check your IP address
   ip addr show  # Linux
   ifconfig      # macOS
   
   # Verify network connectivity
   ping 8.8.8.8
   ```

2. **Firewall Blocking**
   ```bash
   # Temporarily disable firewall (testing only)
   sudo ufw disable        # Ubuntu
   sudo systemctl stop firewalld  # RHEL/CentOS
   ```

3. **Network Configuration**
   ```bash
   # Check routing table
   route -n      # Linux
   netstat -rn   # macOS
   ```

#### Database Errors

**Symptoms:** SQLite errors or corruption
**Solution:**
```bash
# Check database integrity
sqlite3 logs/network_monitor.db "PRAGMA integrity_check;"

# Backup and recreate if corrupted
mv logs/network_monitor.db logs/network_monitor.db.backup
python3 main.py discover --fast  # Recreates database
```

#### Memory/Performance Issues

**Symptoms:** High memory usage during monitoring
**Causes & Solutions:**

1. **High Traffic Network**
   ```bash
   # Monitor specific interface only
   sudo python3 main.py monitor --interface lo  # Loopback for testing
   ```

2. **Long Running Sessions**
   ```bash
   # Restart monitoring periodically
   # (Use automation scripts from Advanced Usage)
   ```

### Debug Mode Troubleshooting

#### Enable Maximum Debugging
```bash
# All modes support debug flag
python3 main.py discover --debug
sudo python3 main.py monitor --debug
python3 main.py analyze --debug
```

#### Debug Output Analysis
```bash
# Monitor debug log
tail -f logs/network_monitor.log

# Search for specific errors
grep -i error logs/network_monitor.log
grep -i warning logs/network_monitor.log
```

---

## Technical Details

### Network Discovery Methods

#### ARP Table Parsing
```bash
# Manual ARP table check
arp -a

# Expected format parsing:
# router.local (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on en0
```

#### Ping Sweep Implementation
- Multithreaded ping execution (10-20 workers)
- 1-second timeout per host
- ICMP echo request method
- Fallback to TCP connect for ICMP-filtered hosts

#### Nmap Integration
```bash
# Service detection scan
nmap -sV -T4 --version-intensity 3 192.168.1.100

# OS detection scan  
nmap -O 192.168.1.100
```

### Packet Capture Technology

#### Scapy Integration
- Raw packet capture using Berkeley Packet Filter (BPF)
- Layer 2/3/4 protocol dissection
- Real-time packet processing pipeline
- Memory-efficient streaming analysis

#### Traffic Classification Algorithm
```python
def determine_direction(src_ip, dst_ip):
    src_local = is_local_ip(src_ip)
    dst_local = is_local_ip(dst_ip)
    
    if src_local and dst_local:
        return 'internal'
    elif src_local and not dst_local:
        return 'outbound'
    elif not src_local and dst_local:
        return 'inbound'
    else:
        return 'transit'
```

### Performance Characteristics

#### Discovery Performance
- **Network /24:** ~30-60 seconds
- **Network /16:** ~10-20 minutes  
- **Fast mode:** 50% faster, 70% accuracy

#### Monitor Performance
- **Packet Rate:** Up to 10,000 pps
- **Memory Usage:** ~50MB baseline + 1MB per 1000 flows
- **CPU Usage:** 5-15% on modern systems

#### Analysis Performance
- **Small Dataset (<1000 flows):** <1 second
- **Medium Dataset (<10000 flows):** 1-5 seconds
- **Large Dataset (>10000 flows):** 5-30 seconds

---

## Best Practices

### Operational Security

#### Permission Management
```bash
# Create dedicated user for monitoring
sudo useradd -r -s /bin/false tracer-monitor

# Set up sudo rules for monitoring
echo "tracer-monitor ALL=(ALL) NOPASSWD: /usr/bin/python3 /path/to/main.py monitor*" > /etc/sudoers.d/tracer
```

#### Network Authorization
- **Always obtain written permission** before monitoring any network
- **Document monitoring activities** in security logs
- **Notify network administrators** of monitoring activities
- **Comply with local privacy laws** and regulations

#### Data Protection
```bash
# Encrypt sensitive data at rest
gpg --cipher-algo AES256 --compress-algo 1 --symmetric logs/network_monitor.db

# Secure log file permissions
chmod 600 logs/network_monitor.log
chown $(whoami):$(whoami) logs/*
```

### Monitoring Strategy

#### Baseline Establishment
```bash
# Week 1: Establish baseline
for i in {1..7}; do
    python3 main.py discover --summary
    sudo timeout 3600 python3 main.py monitor
    python3 main.py analyze --export
    sleep 86400  # 24 hours
done
```

#### Anomaly Detection
```bash
# Daily comparison against baseline
python3 main.py analyze --security --export
python3 compare_with_baseline.py  # Custom script
```

#### Regular Maintenance
```bash
# Weekly database maintenance
sqlite3 logs/network_monitor.db "VACUUM;"
sqlite3 logs/network_monitor.db "ANALYZE;"

# Monthly log rotation
mv logs/network_monitor.log logs/network_monitor_$(date +%Y%m).log
```

### Environment-Specific Guidelines

#### Home Network
- **Recommended Usage:** Daily discovery, weekly monitoring
- **Profile Focus:** Device inventory, bandwidth usage
- **Security Focus:** Unknown device detection

#### Corporate Network
- **Recommended Usage:** Coordinated with IT security team
- **Profile Focus:** Compliance monitoring, asset tracking
- **Security Focus:** Policy violation detection

#### Security Testing
- **Recommended Usage:** Comprehensive monitoring during tests
- **Profile Focus:** Complete traffic analysis
- **Security Focus:** Attack pattern identification

---

## Integration & Automation

### CI/CD Integration

#### GitHub Actions Example
```yaml
name: Network Security Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  network-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.8'
    - name: Install dependencies
      run: |
        python -m venv t
        source t/bin/activate
        pip install -r requirements.txt
    - name: Run network discovery
      run: |
        source t/bin/activate
        python3 main.py discover --fast --summary
    - name: Security analysis
      run: |
        source t/bin/activate
        python3 main.py analyze --security --export
```

### API Integration

#### REST API Wrapper Example
```python
#!/usr/bin/env python3
from flask import Flask, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route('/api/discover')
def api_discover():
    result = subprocess.run(['python3', 'main.py', 'discover', '--fast'], 
                          capture_output=True, text=True)
    return jsonify({'status': 'success', 'output': result.stdout})

@app.route('/api/analyze')  
def api_analyze():
    result = subprocess.run(['python3', 'main.py', 'analyze', '--export'], 
                          capture_output=True, text=True)
    return jsonify({'status': 'success', 'output': result.stdout})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### Monitoring Integration

#### Nagios Plugin Example
```bash
#!/bin/bash
# check_tracer_security.sh

cd /path/to/tracer
python3 main.py analyze --security > /tmp/tracer_security.out 2>&1

CONCERNS=$(grep "Security Concerns Found:" /tmp/tracer_security.out | awk '{print $4}')

if [ "$CONCERNS" -gt 5 ]; then
    echo "CRITICAL - $CONCERNS security concerns found"
    exit 2
elif [ "$CONCERNS" -gt 2 ]; then
    echo "WARNING - $CONCERNS security concerns found"  
    exit 1
else
    echo "OK - $CONCERNS security concerns found"
    exit 0
fi
```

---

## Error Codes & Exit Status

### Exit Codes
- **0:** Success
- **1:** General error  
- **2:** Permission denied
- **3:** Network error
- **4:** Database error
- **5:** Invalid arguments

### Error Messages

#### Discovery Errors
- `[!] Network range detection failed` - Cannot determine local network
- `[!] No active devices found` - Network unreachable or filtered
- `[!] nmap not available` - Missing required dependency

#### Monitor Errors  
- `[!] Packet capture dependencies not available` - Missing Scapy
- `[!] No network interface found` - Interface detection failed
- `[!] Permission denied for packet capture` - Requires root privileges

#### Analysis Errors
- `[!] Database not found` - Run discovery/monitor first
- `[!] No data available for analysis` - Empty database
- `[!] Export failed` - File system permissions

---

## License & Legal

This tool is released under the MIT License. 

**Important Legal Considerations:**

- **Authorization Required:** Always obtain proper authorization before monitoring any network
- **Privacy Laws:** Comply with local data protection and privacy regulations
- **Corporate Policies:** Ensure compliance with organizational security policies
- **Responsible Use:** This tool is for legitimate network administration and security purposes only

**Disclaimer:** Users are responsible for ensuring their use of this tool complies with applicable laws and regulations. The authors assume no liability for misuse of this software.

---

## Support & Community

For issues, questions, or contributions:

- **GitHub Issues:** Report bugs and request features
- **Documentation:** This guide covers comprehensive usage
- **Community:** Share experiences and best practices

**Remember:** Network monitoring requires careful consideration of legal, ethical, and technical factors. Always use this tool responsibly and in accordance with applicable policies and regulations. 