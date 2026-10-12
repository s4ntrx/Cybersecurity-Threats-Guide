
## Detection Scripts

### arp_spoof_detector.py
#!/usr/bin/env python3
"""
ARP Spoofing Detector
Location: 01-network-security/man-in-the-middle/detection/arp_spoof_detector.py

This script detects ARP spoofing/poisoning attacks by monitoring ARP tables,
analyzing network traffic, and identifying suspicious ARP activities.
"""

import scapy.all as scapy
import threading
import time
import argparse
import os
import sys
import signal
from collections import defaultdict
from datetime import datetime
import json
import subprocess
import re
from colorama import init, Fore, Style

init(autoreset=True)

class ARPSpoofDetector:
    def __init__(self, interface="eth0", check_interval=5, threshold=2, log_file="arp_alerts.log"):
        """
        Initialize ARP Spoof Detector
        
        Args:
            interface: Network interface to monitor
            check_interval: Seconds between ARP table checks
            threshold: Number of changes before alert
            log_file: File to log alerts
        """
        self.interface = interface
        self.check_interval = check_interval
        self.threshold = threshold
        self.log_file = log_file
        
        # Data structures
        self.ip_mac_mapping = {}  # Known IP -> MAC mappings
        self.arp_changes = defaultdict(int)  # IP -> change count
        self.arp_packets = []  # Captured ARP packets
        self.suspicious_ips = set()
        self.blocked_ips = set()
        
        # Network info
        self.get_network_info()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'arp_requests': 0,
            'arp_replies': 0,
            'suspicious_activities': 0,
            'alerts_triggered': 0,
            'start_time': time.time()
        }
        
        # Control flags
        self.running = True
        self.monitoring = False
        
    def get_network_info(self):
        """Get network configuration"""
        try:
            # Get IP and MAC of interface
            result = subprocess.run(['ip', 'addr', 'show', self.interface], 
                                   capture_output=True, text=True)
            
            # Extract IP
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if ip_match:
                self.local_ip = ip_match.group(1)
            else:
                self.local_ip = None
            
            # Extract MAC
            mac_match = re.search(r'link/ether ([\da-f:]+)', result.stdout)
            if mac_match:
                self.local_mac = mac_match.group(1)
            else:
                self.local_mac = None
            
            # Get gateway IP
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                   capture_output=True, text=True)
            gateway_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if gateway_match:
                self.gateway_ip = gateway_match.group(1)
            else:
                self.gateway_ip = None
            
            print(f"{Fore.GREEN}[*] Local IP: {self.local_ip}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[*] Local MAC: {self.local_mac}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[*] Gateway IP: {self.gateway_ip}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error getting network info: {e}{Style.RESET_ALL}")
    
    def get_arp_table(self):
        """Get the current ARP table as {ip: mac}. Uses /proc/net/arp on Linux, `arp -an` elsewhere."""
        arp_table = {}
        try:
            if os.path.exists('/proc/net/arp'):
                with open('/proc/net/arp') as handle:
                    next(handle, None)                       # header
                    for line in handle:
                        parts = line.split()
                        if len(parts) >= 4 and parts[2] != '0x0' and parts[3] != '00:00:00:00:00:00':
                            arp_table[parts[0]] = parts[3].lower()
            else:
                output = subprocess.run(['arp', '-an'], capture_output=True, text=True).stdout
                for ip, mac in re.findall(r'\(([\d.]+)\) at ([0-9a-fA-F:]{11,17})', output):
                    arp_table[ip] = mac.lower().replace('-', ':')
        except (OSError, subprocess.SubprocessError) as e:
            print(f"{Fore.YELLOW}[!] Error getting ARP table: {e}{Style.RESET_ALL}")

        return arp_table
    
    def check_arp_table_changes(self):
        """Monitor ARP table for suspicious changes"""
        while self.running:
            try:
                current_arp = self.get_arp_table()
                
                # Compare with known mappings
                for ip, mac in current_arp.items():
                    # Skip our own IP
                    if ip == self.local_ip:
                        continue
                    
                    if ip in self.ip_mac_mapping:
                        if self.ip_mac_mapping[ip] != mac:
                            # ARP change detected
                            self.arp_changes[ip] += 1
                            
                            if self.arp_changes[ip] >= self.threshold:
                                self.detect_arp_spoofing(ip, self.ip_mac_mapping[ip], mac)
                    else:
                        # New IP in ARP table
                        self.ip_mac_mapping[ip] = mac
                
                # Check for duplicate MACs (possible MITM)
                mac_to_ips = defaultdict(list)
                for ip, mac in current_arp.items():
                    mac_to_ips[mac].append(ip)
                
                for mac, ips in mac_to_ips.items():
                    if len(ips) > 1 and mac != self.local_mac:
                        self.trigger_alert(
                            "DUPLICATE_MAC",
                            f"MAC {mac} associated with multiple IPs: {', '.join(ips)}"
                        )
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error in ARP monitoring: {e}{Style.RESET_ALL}")
                time.sleep(self.check_interval)
    
    def packet_handler(self, packet):
        """Process captured ARP packets"""
        if not self.running:
            return
        
        self.stats['total_packets'] += 1
        
        if packet.haslayer(scapy.ARP):
            arp = packet[scapy.ARP]
            
            if arp.op == 1:  # ARP Request
                self.stats['arp_requests'] += 1
                self.analyze_arp_request(arp)
                
            elif arp.op == 2:  # ARP Reply
                self.stats['arp_replies'] += 1
                self.analyze_arp_reply(arp)
    
    def analyze_arp_request(self, arp):
        """Analyze ARP request packets"""
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        
        # Check for suspicious ARP requests
        if src_ip == self.gateway_ip and src_mac != self.get_mac_by_ip(src_ip):
            self.detect_arp_spoofing(src_ip, self.get_mac_by_ip(src_ip), src_mac)
    
    def analyze_arp_reply(self, arp):
        """Analyze ARP reply packets"""
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        
        # Check for unsolicited ARP replies
        if src_ip in self.ip_mac_mapping:
            if self.ip_mac_mapping[src_ip] != src_mac:
                self.detect_arp_spoofing(src_ip, self.ip_mac_mapping[src_ip], src_mac)
        else:
            # New ARP reply, store mapping
            self.ip_mac_mapping[src_ip] = src_mac
        
        # Check if gateway IP is being spoofed
        if src_ip == self.gateway_ip and src_mac != self.local_mac:
            self.trigger_alert(
                "GATEWAY_SPOOF",
                f"Gateway {self.gateway_ip} has MAC {src_mac} (expected different)"
            )
    
    def detect_arp_spoofing(self, ip, old_mac, new_mac):
        """Detect ARP spoofing attempts"""
        self.stats['suspicious_activities'] += 1
        
        alert_msg = (f"ARP SPOOFING DETECTED: IP {ip} changed from "
                    f"{old_mac} to {new_mac}")
        
        # Check if this is a known attacker
        if new_mac in self.suspicious_ips:
            alert_msg += " (Known attacker MAC)"
            self.restore_known_good(ip, old_mac)
        
        self.trigger_alert("ARP_SPOOF", alert_msg, {
            'ip': ip,
            'old_mac': old_mac,
            'new_mac': new_mac,
            'change_count': self.arp_changes[ip]
        })
        
        # Add to suspicious set
        self.suspicious_ips.add(new_mac)
    
    auto_respond = False

    def restore_known_good(self, ip, good_mac):
        """Pin the LAST KNOWN-GOOD MAC for `ip` as a static ARP entry (opt-in, needs root).

        The earlier version ran `arp -s <ip> <new_mac>` and `iptables -A INPUT -s <ip> -j DROP`.
        Here <ip> is the address being impersonated (often the gateway) and <new_mac> is the
        attacker, so that pinned the poisoned mapping permanently and cut off the real host.
        """
        if not self.auto_respond or ip in self.blocked_ips:
            return
        try:
            subprocess.run(['arp', '-s', ip, good_mac], check=True)
            self.blocked_ips.add(ip)
            print(f"{Fore.RED}[!] Pinned {ip} -> {good_mac} (last known good){Style.RESET_ALL}")
        except (OSError, subprocess.SubprocessError) as e:
            print(f"{Fore.YELLOW}[!] Could not pin ARP entry: {e}{Style.RESET_ALL}")

    def get_mac_by_ip(self, ip):
        """Get MAC address for an IP from the ARP table."""
        return self.get_arp_table().get(ip)

    def trigger_alert(self, alert_type, message, data=None):
        """Trigger security alert"""
        self.stats['alerts_triggered'] += 1
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert = {
            'timestamp': timestamp,
            'type': alert_type,
            'message': message,
            'data': data or {}
        }
        
        # Print alert
        print(f"\n{Fore.RED}🚨 ALERT [{timestamp}]{Style.RESET_ALL}")
        print(f"{Fore.RED}   Type: {alert_type}{Style.RESET_ALL}")
        print(f"{Fore.RED}   Message: {message}{Style.RESET_ALL}")
        
        # Log to file
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] {alert_type}: {message}\n")
            if data:
                f.write(f"    Data: {json.dumps(data)}\n")
        
        # Save to JSON
        try:
            with open('arp_alerts.json', 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except:
            pass
    
    def start_monitoring(self):
        """Start ARP spoofing detection"""
        print(f"\n{Fore.CYAN}🚀 Starting ARP Spoofing Detector...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Interface: {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Check Interval: {self.check_interval}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Threshold: {self.threshold} changes{Style.RESET_ALL}")
        
        # Start ARP table monitoring thread
        monitor_thread = threading.Thread(target=self.check_arp_table_changes)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start packet capture
        self.monitoring = True
        print(f"{Fore.GREEN}[*] Monitoring for ARP spoofing attacks...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}   Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        try:
            # Capture ARP packets
            scapy.sniff(iface=self.interface, 
                       filter="arp", 
                       prn=self.packet_handler, 
                       store=False)
        except PermissionError:
            print(f"{Fore.RED}[!] Permission denied. Run with sudo.{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.monitoring = False
        
        # Print statistics
        duration = time.time() - self.stats['start_time']
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 DETECTOR STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"  Runtime: {duration:.2f} seconds")
        print(f"  Total Packets: {self.stats['total_packets']}")
        print(f"  ARP Requests: {self.stats['arp_requests']}")
        print(f"  ARP Replies: {self.stats['arp_replies']}")
        print(f"  Suspicious Activities: {self.stats['suspicious_activities']}")
        print(f"  Alerts Triggered: {self.stats['alerts_triggered']}")
        print(f"  Blocked IPs: {len(self.blocked_ips)}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    print(f"\n{Fore.YELLOW}[*] Stopping detector...{Style.RESET_ALL}")
    detector.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='ARP Spoofing Detector')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-t', '--threshold', type=int, default=2, 
                       help='ARP changes before alert')
    parser.add_argument('-c', '--check-interval', type=int, default=5,
                       help='Seconds between ARP table checks')
    parser.add_argument('-l', '--log', default='arp_alerts.log', help='Log file')
    parser.add_argument('--auto-respond', action='store_true',
                        help='Pin the last known-good MAC as a static ARP entry on detection (needs root)')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║      ARP Spoofing Detector          ║
    ║    Man-in-the-Middle Detection      ║
    ║       FOR EDUCATIONAL USE ONLY       ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Check root privileges
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] This script requires root privileges.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please run with: sudo python3 arp_spoof_detector.py{Style.RESET_ALL}")
        sys.exit(1)
    
    global detector
    detector = ARPSpoofDetector(args.interface, args.check_interval, 
                                args.threshold, args.log)
    detector.auto_respond = args.auto_respond
    
    # Set signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start monitoring
    detector.start_monitoring()

if __name__ == "__main__":
    main()
