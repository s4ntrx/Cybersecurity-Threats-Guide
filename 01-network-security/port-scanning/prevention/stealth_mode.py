#!/usr/bin/env python3
"""
Stealth Mode - Port Knocking Implementation
This script implements port knocking to hide services from port scanners.
Services only become available after a specific sequence of connection attempts.
"""

import socket
import threading
import time
import argparse
import os
import sys
import subprocess
import hashlib
import hmac
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import signal
from colorama import init, Fore, Style

init(autoreset=True)

class PortKnockingServer:
    """
    Port Knocking Server
    
    Hides services behind a sequence of port knocks. Only clients that
    provide the correct knock sequence can access the protected service.
    """
    
    def __init__(self, knock_sequence=[1234, 2345, 3456], target_port=22, 
                 timeout=30, interface='0.0.0.0', log_file="knock.log"):
        """
        Initialize port knocking server
        
        Args:
            knock_sequence: List of ports to knock in order
            target_port: Port to protect (usually SSH - 22)
            timeout: Seconds before knock sequence expires
            interface: Interface to listen on
            log_file: Log file path
        """
        self.knock_sequence = knock_sequence
        self.target_port = target_port
        self.timeout = timeout
        self.interface = interface
        self.log_file = log_file
        
        # Track knock states per IP
        self.knock_states = defaultdict(lambda: {
            'stage': 0,
            'timestamp': time.time(),
            'attempts': deque(maxlen=100)
        })
        
        # Track allowed IPs
        self.allowed_ips = {}
        
        # Statistics
        self.stats = {
            'total_knocks': 0,
            'successful_knocks': 0,
            'failed_knocks': 0,
            'ips_allowed': 0,
            'start_time': time.time()
        }
        
        # Control flags
        self.running = True
        
    def log(self, message, level="INFO"):
        """Log message to file and console"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {level}: {message}"
        
        # Console output
        if level == "ALERT":
            print(f"{Fore.RED}{log_entry}{Style.RESET_ALL}")
        elif level == "SUCCESS":
            print(f"{Fore.GREEN}{log_entry}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}{log_entry}{Style.RESET_ALL}")
        
        # File logging
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
    
    def handle_knock(self, client_ip, port):
        """Handle a knock on a port"""
        self.stats['total_knocks'] += 1
        
        # Get current state for this IP
        state = self.knock_states[client_ip]
        current_time = time.time()
        
        # Check if sequence expired
        if current_time - state['timestamp'] > self.timeout:
            state['stage'] = 0
        
        expected_port = self.knock_sequence[state['stage']] if state['stage'] < len(self.knock_sequence) else None
        
        # Log the knock
        self.log(f"Knock from {client_ip} on port {port} (stage {state['stage'] + 1})")
        state['attempts'].append({'port': port, 'time': current_time})
        
        # Check if this is the correct next knock
        if expected_port and port == expected_port:
            state['stage'] += 1
            state['timestamp'] = current_time
            
            self.log(f"Correct knock from {client_ip} - stage {state['stage']}/{len(self.knock_sequence)}", "SUCCESS")
            
            # Check if sequence complete
            if state['stage'] == len(self.knock_sequence):
                self.grant_access(client_ip)
                state['stage'] = 0  # Reset for next time
        else:
            # Wrong knock - reset
            state['stage'] = 0
            state['timestamp'] = current_time
            self.stats['failed_knocks'] += 1
            self.log(f"Wrong knock from {client_ip} on port {port}", "ALERT")
    
    def grant_access(self, client_ip):
        """Grant access to protected service"""
        expiry = time.time() + self.timeout
        self.allowed_ips[client_ip] = expiry
        self.stats['successful_knocks'] += 1
        self.stats['ips_allowed'] = len(self.allowed_ips)
        
        self.log(f"Access granted to {client_ip} for {self.timeout} seconds", "SUCCESS")
        
        # Add iptables rule to allow access
        self.add_iptables_rule(client_ip)
    
    def _iptables(self, flag, ip, check=False, quiet=False):
        """Run an iptables allow-rule change WITHOUT a shell. The address is validated first, so a
        crafted value can never be interpreted as extra shell commands (the old code interpolated
        it into a shell=True command line)."""
        ip = str(ipaddress.ip_address(ip))
        return subprocess.run(
            ['iptables', f'-{flag}', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(self.target_port), '-j', 'ACCEPT'],
            check=check, stderr=subprocess.DEVNULL if quiet else None)

    def add_iptables_rule(self, client_ip):
        """Add iptables rule to allow access"""
        try:
            # Remove old rule if exists
            self._iptables('D', client_ip, quiet=True)
            
            # Add new rule
            self._iptables('I', client_ip, check=True)
            
            self.log(f"Added iptables rule for {client_ip} to access port {self.target_port}")
        except Exception as e:
            self.log(f"Error adding iptables rule: {e}", "ERROR")
    
    def remove_expired_access(self):
        """Remove expired access grants"""
        current_time = time.time()
        expired = []
        
        for ip, expiry in self.allowed_ips.items():
            if current_time > expiry:
                expired.append(ip)
        
        for ip in expired:
            try:
                self._iptables('D', ip, check=True)
                del self.allowed_ips[ip]
                self.log(f"Access expired for {ip}")
            except Exception as e:
                self.log(f"Error removing iptables rule: {e}", "ERROR")
    
    def knock_listener(self, port):
        """Listen for knocks on a specific port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((self.interface, port))
            sock.listen(5)
            sock.settimeout(1)
            
            self.log(f"Listening for knocks on port {port}")
            
            while self.running:
                try:
                    client, addr = sock.accept()
                    client.close()
                    self.handle_knock(addr[0], port)
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f"Error on port {port}: {e}", "ERROR")
                    
        except Exception as e:
            self.log(f"Failed to listen on port {port}: {e}", "ERROR")
        finally:
            sock.close()
    
    def start(self):
        """Start the port knocking server"""
        self.log(f"Starting Port Knocking Server")
        self.log(f"Knock sequence: {' -> '.join(map(str, self.knock_sequence))}")
        self.log(f"Protected port: {self.target_port}")
        self.log(f"Timeout: {self.timeout} seconds")
        
        # Start listener threads for each knock port
        threads = []
        for port in self.knock_sequence:
            thread = threading.Thread(target=self.knock_listener, args=(port,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_loop)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        # Start stats thread
        stats_thread = threading.Thread(target=self.stats_loop)
        stats_thread.daemon = True
        stats_thread.start()
        
        self.log(f"Server running. Press Ctrl+C to stop.")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def cleanup_loop(self):
        """Periodically clean up expired access"""
        while self.running:
            time.sleep(10)
            self.remove_expired_access()
    
    def stats_loop(self):
        """Periodically display statistics"""
        while self.running:
            time.sleep(30)
            self.display_stats()
    
    def display_stats(self):
        """Display server statistics"""
        uptime = time.time() - self.stats['start_time']
        
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 PORT KNOCKING STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"  Uptime: {int(uptime)} seconds")
        print(f"  Total knocks: {self.stats['total_knocks']}")
        print(f"  Successful knocks: {self.stats['successful_knocks']}")
        print(f"  Failed knocks: {self.stats['failed_knocks']}")
        print(f"  Currently allowed IPs: {len(self.allowed_ips)}")
        print(f"  Total unique IPs allowed: {self.stats['ips_allowed']}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    def stop(self):
        """Stop the server"""
        self.log("Stopping Port Knocking Server...")
        self.running = False
        
        # Remove all iptables rules
        for ip in list(self.allowed_ips.keys()):
            try:
                self._iptables('D', ip, check=True)
            except:
                pass
        
        self.log("Server stopped")

class PortKnockingClient:
    """
    Port Knocking Client
    
    Sends the knock sequence to a server to gain access.
    """
    
    def __init__(self, server_ip, knock_sequence, timeout=5):
        """
        Initialize port knocking client
        
        Args:
            server_ip: Server IP address
            knock_sequence: List of ports to knock
            timeout: Connection timeout in seconds
        """
        self.server_ip = server_ip
        self.knock_sequence = knock_sequence
        self.timeout = timeout
    
    def knock(self, port):
        """Send a single knock"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.server_ip, port))
            # Immediately close - we just want the connection attempt
            sock.close()
            return True
        except:
            return False
        finally:
            sock.close()
    
    def execute_knock_sequence(self, delay=0.5):
        """Execute the full knock sequence"""
        print(f"{Fore.CYAN}[*] Executing knock sequence to {self.server_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    Sequence: {' -> '.join(map(str, self.knock_sequence))}{Style.RESET_ALL}")
        
        successful = 0
        for i, port in enumerate(self.knock_sequence):
            print(f"  Knock {i+1}: port {port}... ", end='')
            if self.knock(port):
                print(f"{Fore.GREEN}✓{Style.RESET_ALL}")
                successful += 1
            else:
                print(f"{Fore.RED}✗{Style.RESET_ALL}")
            
            time.sleep(delay)
        
        if successful == len(self.knock_sequence):
            print(f"\n{Fore.GREEN}[✓] Knock sequence complete! Access should be granted.{Style.RESET_ALL}")
            return True
        else:
            print(f"\n{Fore.RED}[✗] Knock sequence failed{Style.RESET_ALL}")
            return False

class SinglePacketAuthorization:
    """
    Single Packet Authorization (SPA) - More secure than port knocking
    Uses encrypted single packets instead of multiple connection attempts
    """
    
    def __init__(self, shared_secret, target_port=22, timeout=30):
        self.shared_secret = shared_secret
        self.target_port = target_port
        self.timeout = timeout
        self.allowed_ips = {}
        
    def generate_token(self, client_ip, timestamp):
        """Generate authorization token"""
        
        message = f"{client_ip}:{timestamp}".encode()
        token = hmac.new(self.shared_secret.encode(), message, hashlib.sha256).hexdigest()
        return token
    
    def verify_token(self, client_ip, timestamp, token):
        """Verify authorization token"""
        expected = self.generate_token(client_ip, timestamp)
        return hmac.compare_digest(token, expected)

def demonstrate_knocking():
    """Demonstrate port knocking"""
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║     Port Knocking Demonstration       ║
    ║       Stealth Mode Example            ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Configuration
    knock_sequence = [1234, 2345, 3456]
    protected_port = 22
    
    print(f"{Fore.GREEN}Configuration:{Style.RESET_ALL}")
    print(f"  Knock Sequence: {' -> '.join(map(str, knock_sequence))}")
    print(f"  Protected Port: {protected_port}")
    print(f"  Timeout: 30 seconds\n")
    
    # Create server (in thread for demo)
    server = PortKnockingServer(knock_sequence, protected_port)
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(2)  # Let server start
    
    # Create client
    client = PortKnockingClient('127.0.0.1', knock_sequence)
    
    # Execute knock sequence
    print(f"{Fore.YELLOW}[*] Client attempting to knock...{Style.RESET_ALL}")
    success = client.execute_knock_sequence()
    
    if success:
        print(f"\n{Fore.GREEN}[✓] Client should now have access to port {protected_port}{Style.RESET_ALL}")
    
    # Show statistics
    time.sleep(2)
    server.display_stats()
    
    # Stop server
    server.stop()

def main():
    parser = argparse.ArgumentParser(description='Port Knocking - Stealth Mode')
    parser.add_argument('--server', action='store_true', help='Run as server')
    parser.add_argument('--client', action='store_true', help='Run as client')
    parser.add_argument('--server-ip', default='127.0.0.1', help='Server IP for client mode')
    parser.add_argument('--knock', help='Knock sequence (comma-separated, e.g., "1234,2345,3456")')
    parser.add_argument('--target', type=int, default=22, help='Target port to protect')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds')
    parser.add_argument('--demo', action='store_true', help='Run demonstration')
    
    args = parser.parse_args()
    
    # Parse knock sequence
    knock_sequence = [int(p.strip()) for p in args.knock.split(',')] if args.knock else [1234, 2345, 3456]
    
    if args.demo:
        demonstrate_knocking()
        sys.exit(0)
    
    if args.server:
        print(f"""
        {Fore.CYAN}╔═══════════════════════════════════════╗
        ║     Port Knocking Server            ║
        ║       Stealth Mode Active           ║
        ╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """)
        
        server = PortKnockingServer(knock_sequence, args.target, args.timeout)
        server.start()
    
    elif args.client:
        print(f"""
        {Fore.CYAN}╔═══════════════════════════════════════╗
        ║     Port Knocking Client            ║
        ╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """)
        
        client = PortKnockingClient(args.server_ip, knock_sequence)
        client.execute_knock_sequence()
    
    else:
        print("Use --server for server mode, --client for client mode, or --demo for demonstration")

if __name__ == "__main__":
    main()
