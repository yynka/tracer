```
████████╗██████╗  █████╗  ██████╗███████╗██████╗  ㅤ⠀⠀⠀⠀   
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗ ⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⡆ ⣠⣶⣿⣶⡀
   ██║   ██████╔╝███████║██║     █████╗  ██████╔╝ ⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══██╗ ⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║  ██║ ⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⠋
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ⠀⠀⠀⠀⣾⣿⣿⣧⠀⠻⣿⣿⠿⠉
                                                 ⣰⣿⣿⣿⣿⣿⣿⣿
                                                 ⠸⣿⣿⣿⣿⣿⣿⠏
                                                 ⠀⠈⠛⠿⣿⣿⡟
```
**Real-Time Network Discovery & Traffic Analysis System**

[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#windows)
[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#macos)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#linux)


<span style="font-size: 1.2em; line-height: 1.6em;">

- **Comprehensive device discovery:** Multi-method scanning using ARP, ping sweeps, and nmap for complete network visibility.
- **Real-time packet analysis:** Live traffic monitoring with flow tracking and protocol analysis.
- **Security threat detection:** Identify suspicious activity, data exfiltration, and unknown devices.
- **Intelligent data correlation:** Links device profiles with traffic patterns for enhanced insights.
- **Unified database storage:** SQLite backend for persistent device profiles and traffic statistics.
- **Three-mode operation:** Discover, monitor, and analyze - all in one unified script.
</span>

---

## Operation Modes

### ■ **Discover Mode** (Network Reconnaissance)
- [+] Multi-method device discovery using ARP, ping sweeps, and nmap
- [+] Cross-platform device profiling (macOS, Linux, Windows detection)
- [+] MAC address vendor identification with fallback databases
- [+] Service detection and shared resource enumeration
- [+] Authenticated scanning for enhanced device profiling
- [+] SQLite database storage for persistent device profiles

### ▲ **Monitor Mode** (Real-time Traffic Analysis)
- [+] Live packet capture using Scapy for comprehensive monitoring
- [+] Protocol analysis supporting TCP, UDP, ICMP, and application protocols
- [+] Traffic direction classification (inbound, outbound, internal, transit)
- [+] Flow tracking with connection state and statistics
- [+] Device correlation linking traffic to discovered device profiles
- [+] Real-time statistics with periodic reporting every 30 seconds

### ▪ **Analyze Mode** (Intelligence & Reporting)
- [+] Comprehensive network analysis combining device and traffic data
- [+] Security assessment with anomaly detection capabilities
- [+] High outbound traffic detection for potential data exfiltration
- [+] Unknown device identification with significant network activity
- [+] Protocol analysis for devices using unexpected communication methods
- [+] JSON export functionality for integration with external tools

---

[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#windows)

**Prerequisites:**
- Python 3.6+ from [python.org](https://python.org)
- nmap from [nmap.org/download.html](https://nmap.org/download.html)
- Administrator privileges for packet capture

**Setup:**
```cmd
# Clone repository
git clone https://github.com/yynka/tracer.git
cd tracer

# Create and activate virtual environment
python -m venv t
t\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py --help
```

**Usage:**
```cmd
# Discovery (no admin required)
python main.py discover --fast --summary

# Monitoring (requires Administrator Command Prompt)
python main.py monitor

# Analysis
python main.py analyze --security --export
```

[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#macos)

**Prerequisites:**
```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python nmap
```

**Setup:**
```bash
# Clone repository
git clone https://github.com/yynka/tracer.git
cd tracer

# Create and activate virtual environment
python3 -m venv t
source t/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 main.py --help
```

**Usage:**
```bash
# Discovery
python3 main.py discover --fast --summary

# Monitoring (requires sudo)
sudo python3 main.py monitor

# Analysis
python3 main.py analyze --security --export
```

[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#linux)

**Prerequisites:**

*Ubuntu/Debian:*
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv nmap net-tools build-essential
```

*RHEL/CentOS/Fedora:*
```bash
sudo dnf install python3 python3-pip python3-venv nmap net-tools gcc
```

*Arch Linux:*
```bash
sudo pacman -S python python-pip nmap net-tools
```

**Setup:**
```bash
# Clone repository
git clone https://github.com/yynka/tracer.git
cd tracer

# Create and activate virtual environment
python3 -m venv t
source t/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 main.py --help
```

**Usage:**
```bash
# Discovery
python3 main.py discover --fast --summary

# Monitoring (requires sudo)
sudo python3 main.py monitor

# Analysis
python3 main.py analyze --security --export
```

## Quick Demo

Try the interactive demo to see all features:

```bash
./demo.sh
```

Or explore the command help system:
```bash
python3 main.py --help
python3 main.py discover --help
```

**For detailed usage instructions, see [GUIDE.md](GUIDE.md)**

## Features

### Device Discovery
Tracer identifies a wide range of devices including:
- Network infrastructure (routers, switches, access points, firewalls)
- Computing devices (servers, workstations, laptops, mobile devices)
- IoT devices (smart home devices, cameras, sensors, thermostats)
- Entertainment systems (smart TVs, gaming consoles, streaming devices)
- Network services (printers, NAS devices, media servers, storage arrays)
- Security devices (cameras, access control systems, door locks)

### Real-time Traffic Analysis
For each device discovered, Tracer:
- Tracks traffic patterns (inbound, outbound, internal communications)
- Analyzes protocol usage (TCP, UDP, ICMP, and application protocols)
- Monitors data volumes (bytes transferred, packet counts, connection frequency)
- Maps communication flows (source/destination analysis, port usage)
- Records temporal behavior (activity patterns, peak usage identification)

### Security Analysis
Advanced security features include:
- Anomaly detection based on traffic patterns and data volumes
- Unknown device identification with significant network activity
- Data exfiltration detection through outbound traffic analysis
- Protocol analysis for devices using unexpected communication methods
- Access pattern monitoring for connection attempts and service usage
- Tailored security recommendations for each device type

## Command Reference

### Quick Reference
```bash
# Discovery - Find and profile network devices
python3 main.py discover [--fast] [--summary] [--username USER --password PASS]

# Monitor - Real-time packet capture (requires sudo)
sudo python3 main.py monitor [--interface IFACE]

# Analysis - Analyze collected data  
python3 main.py analyze [--security] [--export]

# Global options
python3 main.py [command] --log-path PATH --debug
```

### Command Options

| Mode | Option | Description |
|------|--------|-------------|
| **Global** | `--log-path PATH` | Custom directory for logs and database |
| **Global** | `--debug` | Enable verbose debug logging |
| **discover** | `--username USER` | Username for device authentication |
| **discover** | `--password PASS` | Password for device authentication |
| **discover** | `--fast` | Quick scan mode (fewer checks) |
| **discover** | `--summary` | Display detailed device summary |
| **monitor** | `--interface IFACE` | Network interface to monitor |
| **analyze** | `--security` | Focus on security analysis |
| **analyze** | `--export` | Export analysis report to JSON |

### Help System
```bash
python3 main.py --help                    # Show all commands
python3 main.py discover --help           # Discovery options
python3 main.py monitor --help            # Monitor options  
python3 main.py analyze --help            # Analysis options
```

**For comprehensive documentation, see [GUIDE.md](GUIDE.md)**

## Sample Reports

### Device Discovery Summary
```
[+] Found 12 active devices
================================================================================
DEVICE DISCOVERY SUMMARY
================================================================================

[1] 192.168.1.1
    Hostname: router.local
    Platform: Unknown
    Vendor: Netgear
    Accessible: Yes

[2] 192.168.1.100  
    Hostname: MacBook-Pro.local
    Platform: macOS
    Vendor: Apple
    Accessible: Yes

[3] 192.168.1.105
    Hostname: iPhone-13.local
    Platform: Unknown
    Vendor: Apple
    Accessible: No
```

### Traffic Analysis Report
```
NETWORK ANALYSIS
================================================================================
Top 10 Devices by Traffic:
Rank      IP Address              Hostname         Platform     Traffic    Protocols
    1     192.168.1.100           MacBook-Pro      macOS        45.2 MB    TCP,UDP,ICMP
    2     192.168.1.1             router.local     Unknown      23.1 MB    TCP,UDP
    3     192.168.1.105           iPhone-13        Unknown      12.4 MB    TCP,UDP

Platform Traffic Analysis:
      macOS:   3 devices,     67.5 MB total,     22.5 MB avg/device
    Windows:   2 devices,     23.1 MB total,     11.6 MB avg/device
    Unknown:   4 devices,     45.7 MB total,     11.4 MB avg/device
```

### Security Analysis Report
```
SECURITY ANALYSIS
================================================================================
Security Concerns Found: 3

• High Outbound Traffic
  Device: 192.168.1.100 (MacBook-Pro.local)
  Details: 45.2 MB outbound vs 12.1 MB inbound

• Unknown Device with Significant Traffic  
  Device: 192.168.1.105 (iPhone-13.local)
  Details: Unknown platform, 12.4 MB total traffic

• Multi-Protocol Activity
  Device: 192.168.1.50 (printer.local)
  Details: Using 6 protocols: TCP,UDP,ICMP,ARP,DHCP,SNMP
```

## Data Storage

Tracer creates a unified SQLite database (`logs/network_monitor.db`) containing:
- **Device profiles** - Discovery data, capabilities, vendor information
- **Traffic statistics** - Per-device byte/packet counts, protocol usage  
- **Flow records** - Communication patterns, connection details
- **Analysis reports** - Security assessments and network insights

## Integration Examples

### Automated Daily Monitoring
```bash
#!/bin/bash
# Complete network assessment workflow

# Discover devices
python3 main.py discover --fast --summary > daily_devices.txt

# Monitor for 1 hour
timeout 3600 sudo python3 main.py monitor &

# Generate security report
python3 main.py analyze --security --export
```

### Continuous Security Monitoring
```bash
#!/bin/bash
# Background monitoring with periodic analysis

sudo python3 main.py monitor &
MONITOR_PID=$!

while true; do
    sleep 1800  # 30 minutes
    python3 main.py analyze --security --export
    echo "$(date): Security analysis completed"
done
```

## Requirements

- Python 3.6+
- Modern operating system (macOS, Linux, Windows)
- Network access with appropriate permissions
- Root privileges for packet capture (monitor mode)

### Python Dependencies
- `scapy` - Packet capture and analysis
- `netifaces` - Network interface detection  
- `python-nmap` - Advanced network scanning
- `psutil` - System and network information
- `paramiko` - SSH connectivity (optional)

## Security Note

Tracer performs passive network monitoring and authorized device discovery. It does not attempt to exploit discovered vulnerabilities or access unauthorized systems. However, network scanning and packet capture can trigger security systems. 

**Always ensure you have authorization to scan and monitor the target network.**

Key considerations:
- Packet capture requires root privileges and may trigger security alerts
- Captured traffic data may contain sensitive information
- Comply with local network monitoring regulations and privacy laws
- Obtain proper authorization before monitoring any network

## Troubleshooting

### Common Issues

**"Permission denied for packet capture"**
```bash
sudo python3 main.py monitor
```

**"No network interface found"**
```bash
# List available interfaces
ifconfig                                    # macOS/Linux
ip addr show                               # Linux

# Specify interface manually  
python3 main.py monitor --interface en0
```

**"Dependencies missing"**
```bash
pip install -r requirements.txt
./setup.sh  # Run automated setup
```

**"No devices discovered"**
- Check network connectivity and firewall settings
- Verify you're on the correct network segment  
- Try debug mode: `python3 main.py discover --debug`
- Ensure nmap is properly installed

**"Database errors"**
- Check write permissions in logs directory
- Verify SQLite is available
- Try deleting existing database to recreate

[MIT License](LICENSE) 