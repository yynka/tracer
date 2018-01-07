#!/usr/bin/env python3

import os
import sys
import json
import time
import threading
import subprocess
import argparse
import signal
import traceback
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set
from collections import defaultdict, deque
import sqlite3
import ipaddress
import socket
import re
import urllib.request
import urllib.error

# Setup logging first
script_dir = Path(__file__).parent
log_dir = script_dir / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(log_dir / 'network_monitor.log'))
    ]
)

# Import required libraries with fallbacks
try:
    import netifaces
    import nmap
    import psutil
    import paramiko
    NETWORK_SCANNER_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Network scanner dependencies missing: {e}")
    NETWORK_SCANNER_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list, get_if_addr
    PACKET_CAPTURE_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Packet capture dependencies missing: {e}")
    PACKET_CAPTURE_AVAILABLE = False

print("\n=== Network Monitoring Suite ===")

# Data structures
@dataclass
class ServiceInfo:
    name: str
    display_name: str
    status: str
    start_type: str

@dataclass
class ShareInfo:
    name: str
    path: str
    description: str

@dataclass
class HistoryEntry:
    timestamp: str
    type: str
    data: Dict

@dataclass
class DeviceProfile:
    ip_address: str
    hostname: str = None
    mac_address: str = None
    vendor: str = None
    computer_name: str = None
    os_version: str = None
    last_user: str = None
    first_seen: str = None
    last_seen: str = None
    platform: str = None
    is_accessible: bool = False
    services: List[ServiceInfo] = None
    shared_resources: List[ShareInfo] = None
    history: List[HistoryEntry] = None

    def __post_init__(self):
        self.services = self.services or []
        self.shared_resources = self.shared_resources or []
        self.history = self.history or []
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

@dataclass
class PacketInfo:
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size: int
    direction: str
    flags: Optional[str] = None
    payload_size: int = 0

@dataclass
class FlowStats:
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_count: int = 0
    total_bytes: int = 0
    first_seen: str = None
    last_seen: str = None
    direction: str = 'unknown'

@dataclass
class DeviceTraffic:
    ip_address: str
    hostname: str = 'Unknown'
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    total_packets_in: int = 0
    total_packets_out: int = 0
    active_connections: int = 0
    protocols_used: Set[str] = None
    first_seen: str = None
    last_seen: str = None

    def __post_init__(self):
        self.protocols_used = self.protocols_used or set()
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()

class NetworkMonitor:
    """Unified network monitoring class combining scanning and packet capture"""
    
    def __init__(self, log_path=str(Path(__file__).parent / "logs")):
        self.log_path = Path(log_path)
        self.log_path.mkdir(parents=True, exist_ok=True)
        
        # Network scanner components
        if NETWORK_SCANNER_AVAILABLE:
            self.nm = nmap.PortScanner()
        
        # Packet tracer components
        self.flows = {}
        self.device_traffic = {}
        self.recent_packets = deque(maxlen=1000)
        self.local_networks = set()
        self.local_ips = set()
        self.running = False
        self.stats_lock = threading.Lock()
        
        # Database setup
        self.db_path = self.log_path / "network_monitor.db"
        self.init_database()
        
        # Load existing device profiles
        self.device_profiles = self.load_device_profiles()
        
        logging.info(f"NetworkMonitor initialized with log_path={log_path}")
    
    def init_database(self):
        """Initialize SQLite database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Device profiles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_profiles (
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
                    profile_data TEXT
                )
            ''')
            
            # Packet flows table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packet_flows (
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
                )
            ''')
            
            # Device traffic stats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_stats (
                    ip_address TEXT PRIMARY KEY,
                    hostname TEXT,
                    total_bytes_in INTEGER,
                    total_bytes_out INTEGER,
                    total_packets_in INTEGER,
                    total_packets_out INTEGER,
                    protocols_used TEXT,
                    first_seen TEXT,
                    last_seen TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logging.info("Database initialized successfully")
            
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")
    
    def load_device_profiles(self):
        """Load device profiles from database and JSON files"""
        profiles = {}
        
        # Load from JSON files (legacy support)
        try:
            for json_file in self.log_path.glob("*.json"):
                if json_file.name.startswith(("packet_analysis_", "network_analysis_")):
                    continue
                    
                try:
                    with open(json_file, 'r') as f:
                        profile_data = json.load(f)
                        ip = profile_data.get('ip_address')
                        if ip:
                            profiles[ip] = profile_data
                except Exception as e:
                    logging.debug(f"Could not load profile from {json_file}: {e}")
        except Exception as e:
            logging.error(f"Error loading device profiles: {e}")
        
        logging.info(f"Loaded {len(profiles)} device profiles")
        return profiles

    # ===========================================
    # NETWORK SCANNER FUNCTIONALITY
    # ===========================================
    
    def get_network_range(self):
        """Detect network range using netifaces"""
        if not NETWORK_SCANNER_AVAILABLE:
            raise Exception("Network scanner dependencies not available")
            
        try:
            interfaces = netifaces.interfaces()
            logging.info(f"Available interfaces: {interfaces}")
            
            # Try common interfaces first
            primary_interface = None
            for iface in ['en0', 'en1', 'eth0', 'wlan0']:
                if iface in interfaces and netifaces.AF_INET in netifaces.ifaddresses(iface):
                    primary_interface = iface
                    break
            
            if not primary_interface:
                raise Exception("No suitable network interface found")

            interface_info = netifaces.ifaddresses(primary_interface)[netifaces.AF_INET][0]
            ip = interface_info['addr']
            netmask = interface_info['netmask']
            
            print(f"[+] Using interface {primary_interface} ({ip})")
            
            # Convert to network base address
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            network = [ip_parts[i] & mask_parts[i] for i in range(4)]
            
            result = {
                'Base': '.'.join(map(str, network)),
                'Prefix': sum(bin(x).count('1') for x in mask_parts),
                'Interface': ip
            }
            
            return result
            
        except Exception as e:
            logging.error(f"Failed to determine network range: {str(e)}")
            raise

    def get_mac_vendor(self, mac: str) -> str:
        """Get MAC vendor with multiple lookup methods"""
        try:
            mac = mac.replace(':', '').replace('-', '').upper()
            if len(mac) < 6:
                return "Unknown"
            
            # Try online API first
            try:
                url = f'https://api.macvendors.com/{mac[:6]}'
                with urllib.request.urlopen(url, timeout=3) as response:
                    vendor = response.read().decode().strip()
                    if vendor and not vendor.startswith('{"errors"'):
                        return vendor
            except:
                pass
            
            # Fallback to local OUI database
            oui_database = {
                '001560': 'Apple, Inc.', '001CF0': 'Apple, Inc.', '001B63': 'Apple, Inc.',
                '0014A5': 'Netgear Inc.', '0050F2': 'Microsoft Corporation',
                '00A0C9': 'Intel Corporation', '00E018': 'Asustek Computer Inc.',
                # Add more as needed
            }
            
            return oui_database.get(mac[:6], "Unknown")
            
        except Exception as e:
            logging.warning(f"Failed to get MAC vendor for {mac}: {str(e)}")
            return "Unknown"

    def scan_network(self, fast_mode=False):
        """Perform network discovery scan"""
        if not NETWORK_SCANNER_AVAILABLE:
            print("[!] Network scanner dependencies not available")
            print("[!] Install with: pip install netifaces python-nmap psutil paramiko")
            return []

        print("[*] Starting network discovery...")
        
        try:
            network_range = self.get_network_range()
            base_ip = network_range['Base']
            ip_parts = base_ip.split('.')
            base_prefix = '.'.join(ip_parts[:-1]) + '.'
            
            active_devices = []
            
            # ARP scan first
            try:
                arp_output = subprocess.check_output(['arp', '-a']).decode()
                arp_devices = set()
                for line in arp_output.split('\n'):
                    if line.strip():
                        ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            if ip.startswith(base_prefix):
                                arp_devices.add(ip)
            except Exception as e:
                logging.error(f"ARP scan failed: {e}")
                arp_devices = set()
            
            # Ping sweep
            print("[*] Performing ping sweep...")
            from concurrent.futures import ThreadPoolExecutor
            
            def ping_host(ip):
                try:
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', ip],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    return ip if result.returncode == 0 else None
                except:
                    return None
            
            max_workers = 10 if fast_mode else 20
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for i in range(1, 255):
                    ip = f"{base_prefix}{i}"
                    futures.append(executor.submit(ping_host, ip))
                
                for future in futures:
                    result = future.result()
                    if result:
                        try:
                            hostname = socket.getfqdn(result)
                        except:
                            hostname = "Unknown"
                        
                        print(f"[+] Found active host: {result} ({hostname})")
                        active_devices.append({
                            'IPAddress': result,
                            'Hostname': hostname
                        })
            
            # Add ARP devices not found in ping
            for arp_ip in arp_devices:
                if not any(device['IPAddress'] == arp_ip for device in active_devices):
                    try:
                        hostname = socket.getfqdn(arp_ip)
                    except:
                        hostname = "Unknown"
                    
                    active_devices.append({
                        'IPAddress': arp_ip,
                        'Hostname': hostname
                    })
            
            print(f"[+] Found {len(active_devices)} active devices")
            return active_devices
            
        except Exception as e:
            logging.error(f"Network scan error: {str(e)}")
            return []

    def profile_device(self, ip, username=None, password=None):
        """Create detailed device profile"""
        print(f"[*] Profiling device: {ip}")
        profile = DeviceProfile(ip)
        
        try:
            # Basic hostname resolution
            try:
                profile.hostname = socket.getfqdn(ip)
            except:
                profile.hostname = ip
            
            # Get MAC address via ARP
            try:
                arp_output = subprocess.check_output(['arp', '-n', ip]).decode()
                for line in arp_output.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                                profile.mac_address = part
                                profile.vendor = self.get_mac_vendor(part)
                                break
            except:
                pass
            
            # Platform detection via nmap
            if hasattr(self, 'nm'):
                try:
                    self.nm.scan(ip, arguments='-sV -T4 --version-intensity 3')
                    if ip in self.nm.all_hosts():
                        host_info = self.nm[ip]
                        if 'osmatch' in host_info and host_info['osmatch']:
                            os_name = host_info['osmatch'][0]['name']
                            if 'Mac OS' in os_name or 'macOS' in os_name:
                                profile.platform = 'macOS'
                            elif 'Linux' in os_name:
                                profile.platform = 'Linux'
                            elif 'Windows' in os_name:
                                profile.platform = 'Windows'
                            profile.os_version = os_name
                except:
                    pass
            
            # Test accessibility
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                profile.is_accessible = (result.returncode == 0)
            except:
                profile.is_accessible = False
            
            print(f"[+] Profile created for {ip} - Platform: {profile.platform or 'Unknown'}")
            
        except Exception as e:
            logging.error(f"Device profiling error for {ip}: {e}")
        
        return profile

    def save_device_profile(self, profile):
        """Save device profile to database and JSON"""
        try:
            # Save to database
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO device_profiles 
                (ip_address, hostname, mac_address, vendor, computer_name, 
                 os_version, platform, is_accessible, first_seen, last_seen, profile_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                profile.ip_address, profile.hostname, profile.mac_address,
                profile.vendor, profile.computer_name, profile.os_version,
                profile.platform, profile.is_accessible, profile.first_seen,
                profile.last_seen, json.dumps(profile.to_dict())
            ))
            
            conn.commit()
            conn.close()
            
            # Also save as JSON for compatibility
            filename = self.log_path / f"{profile.ip_address.replace('.', '_')}.json"
            with open(filename, 'w') as f:
                json.dump(profile.to_dict(), f, indent=2)
            
            logging.info(f"Profile saved for {profile.ip_address}")
            
        except Exception as e:
            logging.error(f"Failed to save profile for {profile.ip_address}: {e}")

    # ===========================================
    # PACKET CAPTURE FUNCTIONALITY
    # ===========================================
    
    def detect_network_config(self):
        """Detect local network configuration for packet analysis"""
        try:
            if psutil:
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            ip = ipaddress.ip_address(addr.address)
                            if not ip.is_loopback:
                                self.local_ips.add(str(ip))
                                
                                if addr.netmask:
                                    try:
                                        network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                                        self.local_networks.add(network)
                                    except:
                                        pass
            
            logging.info(f"Detected local networks: {self.local_networks}")
            
        except Exception as e:
            logging.error(f"Network configuration detection failed: {e}")

    def is_local_ip(self, ip_str):
        """Check if IP is local to our network"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.local_networks:
                if ip in network:
                    return True
            return False
        except:
            return False

    def determine_direction(self, src_ip, dst_ip):
        """Determine packet direction"""
        src_local = self.is_local_ip(src_ip)
        dst_local = self.is_local_ip(dst_ip)
        
        if src_local and dst_local:
            return 'internal'
        elif src_local and not dst_local:
            return 'outbound'
        elif not src_local and dst_local:
            return 'inbound'
        else:
            return 'transit'

    def process_packet(self, packet):
        """Process captured packet"""
        try:
            if not packet.haslayer(IP):
                return
                
            ip_layer = packet[IP]
            timestamp = datetime.now().isoformat()
            
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            size = len(packet)
            
            src_port = None
            dst_port = None
            flags = None
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol_name = 'TCP'
                flags = str(tcp_layer.flags)
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol_name = 'UDP'
            elif packet.haslayer(ICMP):
                protocol_name = 'ICMP'
            else:
                protocol_name = f'IP_{ip_layer.proto}'
            
            direction = self.determine_direction(src_ip, dst_ip)
            
            packet_info = PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name,
                size=size,
                direction=direction,
                flags=flags
            )
            
            self.recent_packets.append(packet_info)
            
            with self.stats_lock:
                self.update_flow_stats(packet_info)
                self.update_device_stats(packet_info)
                
        except Exception as e:
            logging.error(f"Packet processing error: {e}")

    def update_flow_stats(self, packet_info):
        """Update flow statistics"""
        flow_key = f"{packet_info.src_ip}:{packet_info.src_port}->{packet_info.dst_ip}:{packet_info.dst_port}_{packet_info.protocol}"
        
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowStats(
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                protocol=packet_info.protocol,
                first_seen=packet_info.timestamp,
                direction=packet_info.direction
            )
        
        flow = self.flows[flow_key]
        flow.packet_count += 1
        flow.total_bytes += packet_info.size
        flow.last_seen = packet_info.timestamp

    def update_device_stats(self, packet_info):
        """Update device statistics"""
        for ip in [packet_info.src_ip, packet_info.dst_ip]:
            if ip not in self.device_traffic:
                hostname = self.device_profiles.get(ip, {}).get('hostname', 'Unknown')
                self.device_traffic[ip] = DeviceTraffic(
                    ip_address=ip,
                    hostname=hostname
                )
        
        src_device = self.device_traffic[packet_info.src_ip]
        dst_device = self.device_traffic[packet_info.dst_ip]
        
        if packet_info.direction == 'outbound':
            src_device.total_bytes_out += packet_info.size
            src_device.total_packets_out += 1
        elif packet_info.direction == 'inbound':
            dst_device.total_bytes_in += packet_info.size
            dst_device.total_packets_in += 1
        elif packet_info.direction == 'internal':
            src_device.total_bytes_out += packet_info.size
            src_device.total_packets_out += 1
            dst_device.total_bytes_in += packet_info.size  
            dst_device.total_packets_in += 1
        
        src_device.protocols_used.add(packet_info.protocol)
        dst_device.protocols_used.add(packet_info.protocol)
        
        src_device.last_seen = packet_info.timestamp
        dst_device.last_seen = packet_info.timestamp

    def start_packet_capture(self, interface=None):
        """Start packet capture"""
        if not PACKET_CAPTURE_AVAILABLE:
            print("[!] Packet capture dependencies not available")
            print("[!] Install with: pip install scapy")
            return
        
        self.running = True
        self.detect_network_config()
        
        if not interface:
            interfaces = get_if_list()
            for iface in ['en0', 'eth0', 'wlan0']:
                if iface in interfaces:
                    interface = iface
                    break
        
        if not interface:
            print("[!] No network interface found")
            return
        
        print(f"[*] Starting packet capture on interface: {interface}")
        print("[*] Press Ctrl+C to stop capture")
        
        # Start stats thread
        stats_thread = threading.Thread(target=self.stats_worker, daemon=True)
        stats_thread.start()
        
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except KeyboardInterrupt:
            print("\n[*] Stopping packet capture...")
        except Exception as e:
            logging.error(f"Packet capture error: {e}")
        finally:
            self.running = False
            self.save_stats_to_db()

    def stats_worker(self):
        """Background statistics worker"""
        while self.running:
            try:
                time.sleep(30)
                if self.running:
                    self.print_packet_stats()
                    self.save_stats_to_db()
            except Exception as e:
                logging.error(f"Stats worker error: {e}")

    def save_stats_to_db(self):
        """Save packet statistics to database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            with self.stats_lock:
                # Save device stats
                for ip, device in self.device_traffic.items():
                    cursor.execute('''
                        INSERT OR REPLACE INTO device_stats 
                        (ip_address, hostname, total_bytes_in, total_bytes_out,
                         total_packets_in, total_packets_out, protocols_used,
                         first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        device.ip_address, device.hostname,
                        device.total_bytes_in, device.total_bytes_out,
                        device.total_packets_in, device.total_packets_out,
                        ','.join(device.protocols_used),
                        device.first_seen, device.last_seen
                    ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Database save error: {e}")

    def print_packet_stats(self):
        """Print current packet statistics"""
        with self.stats_lock:
            if not self.device_traffic:
                return
                
            print(f"\n{'='*60}")
            print(f"PACKET CAPTURE STATISTICS - {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*60}")
            
            active_flows = len(self.flows)
            total_packets = sum(flow.packet_count for flow in self.flows.values())
            total_bytes = sum(flow.total_bytes for flow in self.flows.values())
            
            print(f"Active Flows: {active_flows}")
            print(f"Total Packets: {total_packets:,}")
            print(f"Total Bytes: {total_bytes:,} ({total_bytes / (1024*1024):.2f} MB)")
            
            # Top devices
            sorted_devices = sorted(
                self.device_traffic.values(),
                key=lambda d: d.total_bytes_in + d.total_bytes_out,
                reverse=True
            )[:5]
            
            print(f"\nTop 5 Active Devices:")
            for device in sorted_devices:
                total_bytes = device.total_bytes_in + device.total_bytes_out
                total_packets = device.total_packets_in + device.total_packets_out
                print(f"  {device.ip_address:15} | {total_packets:6} pkts | {total_bytes:8} bytes")

    # ===========================================
    # ANALYSIS FUNCTIONALITY
    # ===========================================
    
    def analyze_network(self, security_focus=False, export_report=False):
        """Perform comprehensive network analysis"""
        print(f"\n{'='*80}")
        print("NETWORK ANALYSIS")
        print(f"{'='*80}")
        
        # Load data from database
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Get device profiles
        cursor.execute('SELECT * FROM device_profiles')
        device_profiles = {}
        for row in cursor.fetchall():
            ip = row[0]
            device_profiles[ip] = {
                'ip_address': row[0],
                'hostname': row[1],
                'platform': row[6] or 'Unknown',
                'vendor': row[3] or 'Unknown',
                'is_accessible': row[7]
            }
        
        # Get traffic stats
        cursor.execute('SELECT * FROM device_stats ORDER BY total_bytes_in + total_bytes_out DESC')
        traffic_stats = []
        for row in cursor.fetchall():
            traffic_stats.append({
                'ip_address': row[0],
                'hostname': row[1],
                'total_bytes_in': row[2] or 0,
                'total_bytes_out': row[3] or 0,
                'total_packets_in': row[4] or 0,
                'total_packets_out': row[5] or 0,
                'protocols_used': row[6].split(',') if row[6] else []
            })
        
        conn.close()
        
        if not device_profiles and not traffic_stats:
            print("[!] No data available for analysis")
            print("[!] Run 'discover' and 'monitor' commands first")
            return
        
        # Combined analysis
        print(f"\nNetwork Summary:")
        print(f"  Device Profiles: {len(device_profiles)}")
        print(f"  Devices with Traffic: {len(traffic_stats)}")
        
        if traffic_stats:
            total_traffic = sum(d['total_bytes_in'] + d['total_bytes_out'] for d in traffic_stats)
            print(f"  Total Traffic: {total_traffic / (1024*1024):.1f} MB")
        
        # Top devices analysis
        if traffic_stats:
            print(f"\nTop 10 Devices by Traffic:")
            print(f"{'Rank':>4} {'IP Address':>15} {'Hostname':>20} {'Platform':>10} {'Traffic':>12}")
            print("-" * 75)
            
            for i, device in enumerate(traffic_stats[:10], 1):
                profile = device_profiles.get(device['ip_address'], {})
                total_traffic = device['total_bytes_in'] + device['total_bytes_out']
                
                print(f"{i:>4} {device['ip_address']:>15} {device['hostname'][:20]:>20} "
                      f"{profile.get('platform', 'Unknown')[:10]:>10} "
                      f"{total_traffic/(1024*1024):>8.1f} MB")
        
        # Security analysis
        if security_focus and traffic_stats:
            print(f"\n{'='*60}")
            print("SECURITY ANALYSIS")
            print(f"{'='*60}")
            
            concerns = []
            
            for device in traffic_stats:
                # High outbound traffic
                if device['total_bytes_out'] > device['total_bytes_in'] * 2:
                    if device['total_bytes_out'] > 50*1024*1024:
                        concerns.append({
                            'type': 'High Outbound Traffic',
                            'ip': device['ip_address'],
                            'details': f"{device['total_bytes_out']/(1024*1024):.1f} MB outbound"
                        })
                
                # Unknown devices with traffic
                profile = device_profiles.get(device['ip_address'], {})
                if profile.get('platform') == 'Unknown':
                    total_traffic = device['total_bytes_in'] + device['total_bytes_out']
                    if total_traffic > 10*1024*1024:
                        concerns.append({
                            'type': 'Unknown Device with Traffic',
                            'ip': device['ip_address'],
                            'details': f"{total_traffic/(1024*1024):.1f} MB total"
                        })
            
            if concerns:
                print(f"Security Concerns Found: {len(concerns)}")
                for concern in concerns[:5]:
                    print(f"• {concern['type']}: {concern['ip']} - {concern['details']}")
            else:
                print("No obvious security concerns detected")
        
        # Export report
        if export_report:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = self.log_path / f"network_analysis_{timestamp}.json"
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'device_profiles': device_profiles,
                'traffic_stats': traffic_stats,
                'summary': {
                    'total_devices': len(device_profiles),
                    'devices_with_traffic': len(traffic_stats)
                }
            }
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\n[+] Analysis report exported to: {report_file}")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[*] Received interrupt signal, shutting down...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description='Unified Network Monitoring Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py discover --fast                    # Quick network scan
  python main.py discover --username user --password pass  # Detailed scan with credentials
  sudo python main.py monitor --interface en0       # Start packet capture
  python main.py analyze --security --export        # Analyze with security focus
  python main.py analyze --export                   # Full analysis with export
        """
    )
    
    # Global options
    parser.add_argument('--log-path', type=str, default='logs', 
                       help='Directory for logs and database')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug logging')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Discover network devices')
    discover_parser.add_argument('--username', type=str, help='Username for device authentication')
    discover_parser.add_argument('--password', type=str, help='Password for device authentication')
    discover_parser.add_argument('--fast', action='store_true', help='Fast scan mode')
    discover_parser.add_argument('--summary', action='store_true', help='Show detailed summary')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor network traffic')
    monitor_parser.add_argument('--interface', '-i', type=str, help='Network interface to monitor')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze collected data')
    analyze_parser.add_argument('--security', action='store_true', help='Focus on security analysis')
    analyze_parser.add_argument('--export', action='store_true', help='Export analysis report')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        monitor = NetworkMonitor(log_path=args.log_path)
        
        if args.command == 'discover':
            if not NETWORK_SCANNER_AVAILABLE:
                print("[!] Network scanner dependencies not available")
                print("[!] Install with: pip install netifaces python-nmap psutil paramiko")
                return
            
            print("[*] Starting network discovery...")
            devices = monitor.scan_network(fast_mode=args.fast)
            
            if devices:
                print(f"\n[*] Profiling {len(devices)} devices...")
                profiles = []
                
                for device in devices:
                    ip = device['IPAddress']
                    profile = monitor.profile_device(ip, args.username, args.password)
                    profiles.append(profile)
                    monitor.save_device_profile(profile)
                
                if args.summary:
                    print(f"\n{'='*80}")
                    print("DEVICE DISCOVERY SUMMARY")
                    print(f"{'='*80}")
                    
                    for i, profile in enumerate(profiles, 1):
                        print(f"\n[{i}] {profile.ip_address}")
                        print(f"    Hostname: {profile.hostname}")
                        print(f"    Platform: {profile.platform or 'Unknown'}")
                        print(f"    Vendor: {profile.vendor or 'Unknown'}")
                        print(f"    Accessible: {'Yes' if profile.is_accessible else 'No'}")
                
                print(f"\n[+] Discovery complete! Found {len(devices)} devices")
                print(f"[+] Profiles saved to: {args.log_path}")
        
        elif args.command == 'monitor':
            if not PACKET_CAPTURE_AVAILABLE:
                print("[!] Packet capture dependencies not available")
                print("[!] Install with: pip install scapy")
                return
            
            # Check for root privileges
            if os.name != 'nt' and os.geteuid() != 0:
                print("[!] Warning: Packet capture typically requires root privileges")
                print("[!] Try running with: sudo python main.py monitor")
            
            monitor.start_packet_capture(args.interface)
        
        elif args.command == 'analyze':
            monitor.analyze_network(
                security_focus=args.security,
                export_report=args.export
            )
        
    except Exception as e:
        logging.error(f"Command '{args.command}' failed: {e}")
        if args.debug:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 