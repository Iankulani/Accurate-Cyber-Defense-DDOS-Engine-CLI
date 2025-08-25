#!/usr/bin/env python3
"""
Enhanced Cyber Security Network Diagnostic Tool
A comprehensive network security tool with advanced diagnostics capabilities
"""

import argparse
import asyncio
import ipaddress
import json
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
import dns.resolver
import netifaces
import psutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Any, Callable

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, ICMP, TCP, UDP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
    from scapy.sendrecv import send, sr, sr1, srp
    from scapy.volatile import RandShort
except ImportError:
    print("Scapy not installed. Some features may not work properly.")
    
try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Requests library not installed. Web features may not work properly.")

try:
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.ticker import MaxNLocator
except ImportError:
    print("Matplotlib not installed. Graphing features disabled.")

# Color codes for green theme
class Colors:
    GREEN = '\033[92m'
    DARK_GREEN = '\033[32m'
    LIGHT_GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

# Banner for the tool
BANNER = f"""
{Colors.GREEN}{Colors.BOLD}
  ██████ ▓█████  ██▀███   ██▓ ██▓███  ▄▄▄█████▓▓█████  ██▀███  
▒██    ▒ ▓█   ▀ ▓██ ▒ ██▒▓██▒▓██░  ██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄   ▒███   ▓██ ░▄█ ▒▒██▒▓██░ ██▓▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
  ▒   ██▒▒▓█  ▄ ▒██▀▀█▄  ░██░▒██▄█▓▒ ▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
▒██████▒▒░▒████▒░██▓ ▒██▒░██░▒██▒ ░  ░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒  ░ ░ ░ ░  ░  ░▒ ░ ▒░ ▒ ░░▒ ░         ░     ░ ░  ░  ░▒ ░ ▒░
░  ░  ░     ░     ░░   ░  ▒ ░░░         ░         ░     ░░   ░ 
      ░     ░  ░   ░      ░                       ░  ░   ░     
                                                                
{Colors.END}
{Colors.LIGHT_GREEN}Cyber Security Network Diagnostic Tool{Colors.END}
{Colors.DARK_GREEN}Version 3.0 | Advanced Network Operations Suite{Colors.END}
"""

class CyberSecurityTool:
    def __init__(self):
        self.monitoring = False
        self.monitored_ips = set()
        self.traffic_generation = False
        self.traffic_threads = []
        self.config = {
            'telegram_token': None,
            'telegram_chat_id': None,
            'max_threads': 100,
            'ping_timeout': 2,
            'scan_timeout': 1,
            'traffic_intensity': 'medium',
            'dns_servers': ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
            'network_interface': self.get_default_interface(),
            'packet_count_history': [],
            'response_time_history': [],
            'http_user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
            ],
            'http_targets': [
                '/', '/index.html', '/about', '/contact', '/products',
                '/services', '/blog', '/news', '/api/v1/users', '/login'
            ]
        }
        self.ip_list = set()
        self.log_file = "cyber_tool.log"
        self.operation_log = []
        self.executor = ThreadPoolExecutor(max_workers=self.config['max_threads'])
        self.lock = threading.Lock()
        self.hostname_cache = {}
        
    def get_default_interface(self):
        """Get the default network interface"""
        try:
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            return default_interface
        except:
            return "eth0"  # Fallback default
            
    def get_network_info(self):
        """Get detailed network information"""
        try:
            interfaces = netifaces.interfaces()
            network_info = {}
            
            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    network_info[interface] = {
                        'ipv4': addrs[netifaces.AF_INET][0]['addr'],
                        'netmask': addrs[netifaces.AF_INET][0]['netmask'],
                        'broadcast': addrs[netifaces.AF_INET][0].get('broadcast', 'N/A')
                    }
                if netifaces.AF_INET6 in addrs:
                    network_info[interface]['ipv6'] = addrs[netifaces.AF_INET6][0]['addr']
                    
            return network_info
        except Exception as e:
            print(f"{Colors.RED}Error getting network info: {e}{Colors.END}")
            return {}
            
    def log_operation(self, operation: str, details: str = ""):
        """Log operations with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {operation} {details}"
        self.operation_log.append(log_entry)
        
        # Also write to log file
        with open(self.log_file, "a") as f:
            f.write(log_entry + "\n")
            
        return log_entry

    def print_banner(self):
        """Display the tool banner"""
        print(BANNER)
        print(f"{Colors.GREEN}Type 'help' for available commands{Colors.END}\n")

    def print_help(self):
        """Display help information"""
        help_text = f"""
{Colors.BOLD}{Colors.LIGHT_GREEN}Available Commands:{Colors.END}

{Colors.GREEN}General Commands:{Colors.END}
  {Colors.CYAN}help{Colors.END} - Show this help message
  {Colors.CYAN}exit{Colors.END} - Exit the program
  {Colors.CYAN}clear{Colors.END} - Clear the screen
  {Colors.CYAN}view{Colors.END} - View operation log
  {Colors.CYAN}status{Colors.END} - Show current tool status
  {Colors.CYAN}network info{Colors.END} - Show network interface information

{Colors.GREEN}IP Management:{Colors.END}
  {Colors.CYAN}add ip <IP>{Colors.END} - Add IP to monitoring list
  {Colors.CYAN}remove ip <IP>{Colors.END} - Remove IP from monitoring list
  {Colors.CYAN}ping ip <IP>{Colors.END} - Ping an IP address
  {Colors.CYAN}ping ip6 <IPv6>{Colors.END} - Ping an IPv6 address
  {Colors.CYAN}ping hostname <HOSTNAME>{Colors.END} - Ping a hostname

{Colors.GREEN}Monitoring:{Colors.END}
  {Colors.CYAN}start monitoring ip <IP>{Colors.END} - Start monitoring an IP
  {Colors.CYAN}stop{Colors.END} - Stop all monitoring and traffic generation
  {Colors.CYAN}bandwidth{Colors.END} - Monitor bandwidth usage

{Colors.GREEN}Network Diagnostics:{Colors.END}
  {Colors.CYAN}traceroute ip <IP>{Colors.END} - Perform traceroute to IP
  {Colors.CYAN}tcptraceroute ip <IP>{Colors.END} - Perform TCP traceroute
  {Colors.CYAN}udptraceroute ip <IP>{Colors.END} - Perform UDP traceroute
  {Colors.CYAN}test connection{Colors.END} - Test network connectivity
  {Colors.CYAN}scan ip <IP>{Colors.END} - Basic port scan
  {Colors.CYAN}deep scan ip <IP>{Colors.END} - Deep port scan (1-65535)
  {Colors.CYAN}dns lookup <DOMAIN>{Colors.END} - DNS lookup for a domain
  {Colors.CYAN}reverse dns <IP>{Colors.END} - Reverse DNS lookup
  {Colors.CYAN}whois <IP/DOMAIN>{Colors.END} - WHOIS lookup

{Colors.GREEN}Traffic Generation:{Colors.END}
  {Colors.CYAN}generate traffic <IP> <TYPE> <DURATION>{Colors.END} - Generate network traffic to specific IP
  {Colors.CYAN}generate traffic tcp <DURATION>{Colors.END} - Generate TCP traffic to monitored IPs
  {Colors.CYAN}generate traffic udp <DURATION>{Colors.END} - Generate UDP traffic to monitored IPs
  {Colors.CYAN}generate traffic http <DURATION>{Colors.END} - Generate HTTP traffic to monitored IPs
  {Colors.CYAN}generate traffic https <DURATION>{Colors.END} - Generate HTTPS traffic to monitored IPs

{Colors.GREEN}Telegram Integration:{Colors.END}
  {Colors.CYAN}config telegram token <TOKEN>{Colors.END} - Set Telegram bot token
  {Colors.CYAN}config telegram chat_id <ID>{Colors.END} - Set Telegram chat ID
  {Colors.CYAN}test message{Colors.END} - Send test message to Telegram
  {Colors.CYAN}export data{Colors.END} - Export data to Telegram

{Colors.YELLOW}Examples:{Colors.END}
  ping ip 192.168.1.1
  add ip 10.0.0.5
  generate traffic 192.168.1.1 tcp 60
  generate traffic 8.8.8.8 https 30
  deep scan ip 192.168.1.100
  dns lookup example.com
  bandwidth
        """
        print(help_text)

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def validate_ipv6(self, ip: str) -> bool:
        """Validate IPv6 address format"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False

    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve a hostname to an IP address"""
        try:
            # Check cache first
            if hostname in self.hostname_cache:
                if time.time() - self.hostname_cache[hostname]['timestamp'] < 300:  # 5 minute cache
                    return self.hostname_cache[hostname]['ip']
            
            # Resolve using DNS
            result = socket.getaddrinfo(hostname, None)
            ip = result[0][4][0]
            
            # Update cache
            self.hostname_cache[hostname] = {
                'ip': ip,
                'timestamp': time.time()
            }
            
            return ip
        except socket.gaierror:
            return None

    def ping_ip(self, ip: str) -> Tuple[bool, float]:
        """Ping an IP address and return success status and response time"""
        try:
            # Use system ping command for cross-platform compatibility
            param = "-n" if os.name == "nt" else "-c"
            command = ["ping", param, "1", ip]
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=self.config['ping_timeout']
            )
            
            if result.returncode == 0:
                # Extract time from ping output
                time_match = re.search(r"time=([\d.]+) ms", result.stdout)
                response_time = float(time_match.group(1)) if time_match else 0
                return True, response_time
            else:
                return False, 0
        except (subprocess.TimeoutExpired, Exception):
            return False, 0

    def ping_ip6(self, ip: str) -> Tuple[bool, float]:
        """Ping an IPv6 address"""
        try:
            param = "-n" if os.name == "nt" else "-c"
            command = ["ping6", param, "1", ip]
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=self.config['ping_timeout']
            )
            
            if result.returncode == 0:
                time_match = re.search(r"time=([\d.]+) ms", result.stdout)
                response_time = float(time_match.group(1)) if time_match else 0
                return True, response_time
            else:
                return False, 0
        except (subprocess.TimeoutExpired, Exception):
            return False, 0

    def start_monitoring_ip(self, ip: str):
        """Start monitoring an IP address"""
        if not self.validate_ip(ip) and not self.validate_ipv6(ip):
            print(f"{Colors.RED}Invalid IP address format{Colors.END}")
            return
            
        with self.lock:
            self.monitored_ips.add(ip)
            
        print(f"{Colors.GREEN}Started monitoring IP: {ip}{Colors.END}")
        self.log_operation("START_MONITORING", f"IP: {ip}")
        
        # Start monitoring in background thread
        monitor_thread = threading.Thread(
            target=self._monitor_ip, 
            args=(ip,),
            daemon=True
        )
        monitor_thread.start()

    def _monitor_ip(self, ip: str):
        """Background IP monitoring function"""
        while ip in self.monitored_ips:
            if self.validate_ipv6(ip):
                success, response_time = self.ping_ip6(ip)
            else:
                success, response_time = self.ping_ip(ip)
                
            status = f"{Colors.GREEN}UP{Colors.END}" if success else f"{Colors.RED}DOWN{Colors.END}"
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if success:
                print(f"{Colors.DARK_GREEN}[{timestamp}] {ip} is {status} - Response time: {response_time}ms{Colors.END}")
                # Store for graphing
                self.response_time_history.append((time.time(), response_time))
            else:
                print(f"{Colors.RED}[{timestamp}] {ip} is {status}{Colors.END}")
                
            time.sleep(5)  # Check every 5 seconds

    def stop_monitoring(self):
        """Stop all monitoring activities"""
        with self.lock:
            self.monitored_ips.clear()
            
        self.traffic_generation = False
        for thread in self.traffic_threads:
            if thread.is_alive():
                thread.join(timeout=1)
                
        self.traffic_threads.clear()
        print(f"{Colors.GREEN}All monitoring and traffic generation stopped{Colors.END}")
        self.log_operation("STOP_ALL", "Monitoring and traffic generation stopped")

    def generate_traffic(self, target_ip: str, traffic_type: str, duration: int):
        """Generate network traffic to specific IP of specified type and duration"""
        if not self.validate_ip(target_ip) and not self.validate_ipv6(target_ip):
            print(f"{Colors.RED}Invalid target IP address format{Colors.END}")
            return
            
        if traffic_type.lower() not in ["tcp", "udp", "http", "https"]:
            print(f"{Colors.RED}Traffic type must be 'tcp', 'udp', 'http', or 'https'{Colors.END}")
            return
            
        try:
            duration = int(duration)
            if duration <= 0:
                print(f"{Colors.RED}Duration must be a positive integer{Colors.END}")
                return
        except ValueError:
            print(f"{Colors.RED}Duration must be a valid integer{Colors.END}")
            return
            
        print(f"{Colors.GREEN}Starting {traffic_type.upper()} traffic generation to {target_ip} for {duration} seconds{Colors.END}")
        self.log_operation("GENERATE_TRAFFIC", f"Target: {target_ip}, Type: {traffic_type}, Duration: {duration}s")
        
        self.traffic_generation = True
        traffic_thread = threading.Thread(
            target=self._generate_traffic,
            args=(target_ip, traffic_type, duration),
            daemon=True
        )
        traffic_thread.start()
        self.traffic_threads.append(traffic_thread)

    def generate_traffic_to_monitored(self, traffic_type: str, duration: int):
        """Generate network traffic to all monitored IPs"""
        if not self.monitored_ips:
            print(f"{Colors.RED}No IPs being monitored. Add IPs first.{Colors.END}")
            return
            
        print(f"{Colors.GREEN}Starting {traffic_type.upper()} traffic generation to {len(self.monitored_ips)} monitored IPs for {duration} seconds{Colors.END}")
        self.log_operation("GENERATE_TRAFFIC_MONITORED", f"Type: {traffic_type}, Duration: {duration}s")
        
        self.traffic_generation = True
        for target_ip in self.monitored_ips:
            traffic_thread = threading.Thread(
                target=self._generate_traffic,
                args=(target_ip, traffic_type, duration),
                daemon=True
            )
            traffic_thread.start()
            self.traffic_threads.append(traffic_thread)

    def _generate_traffic(self, target_ip: str, traffic_type: str, duration: int):
        """Background traffic generation function"""
        end_time = time.time() + duration
        packet_count = 0
        
        print(f"{Colors.GREEN}Generating {traffic_type.upper()} traffic to {target_ip}{Colors.END}")
        
        while time.time() < end_time and self.traffic_generation:
            try:
                if traffic_type.lower() == "tcp":
                    self._generate_tcp_traffic(target_ip)
                elif traffic_type.lower() == "udp":
                    self._generate_udp_traffic(target_ip)
                elif traffic_type.lower() == "http":
                    self._generate_http_traffic(target_ip)
                elif traffic_type.lower() == "https":
                    self._generate_https_traffic(target_ip)
                    
                packet_count += 1
                
                # Store for graphing
                self.packet_count_history.append((time.time(), packet_count))
                
                # Display progress every 100 packets
                if packet_count % 100 == 0:
                    elapsed = int(time.time() - (end_time - duration))
                    remaining = max(0, int(end_time - time.time()))
                    print(f"{Colors.DARK_GREEN}Generated {packet_count} packets to {target_ip} | Elapsed: {elapsed}s | Remaining: {remaining}s{Colors.END}")
                    
            except Exception as e:
                print(f"{Colors.RED}Error generating traffic to {target_ip}: {e}{Colors.END}")
                
            # Small delay to prevent complete system overload
            time.sleep(0.01)
            
        print(f"{Colors.GREEN}Traffic generation to {target_ip} completed. Total packets sent: {packet_count}{Colors.END}")
        self.log_operation("TRAFFIC_COMPLETED", f"Target: {target_ip}, Packets: {packet_count}, Type: {traffic_type}")

    def _generate_tcp_traffic(self, target_ip: str):
        """Generate TCP traffic to target IP"""
        try:
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            # Try to connect to a random port
            port = random.randint(1024, 65535)
            sock.connect((target_ip, port))
            
            # Send some data
            sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            
            # Close the socket
            sock.close()
        except:
            # Most connections will fail, which is expected
            pass

    def _generate_udp_traffic(self, target_ip: str):
        """Generate UDP traffic to target IP"""
        try:
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Send data to a random port
            port = random.randint(1024, 65535)
            sock.sendto(b"UDP Traffic Generation", (target_ip, port))
            
            # Close the socket
            sock.close()
        except:
            pass

    def _generate_http_traffic(self, target_ip: str):
        """Generate HTTP traffic to target IP"""
        try:
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            # Connect to port 80
            sock.connect((target_ip, 80))
            
            # Generate realistic HTTP request
            user_agent = random.choice(self.config['http_user_agents'])
            target_path = random.choice(self.config['http_targets'])
            
            http_request = (
                f"GET {target_path} HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: {user_agent}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Accept-Language: en-US,en;q=0.5\r\n"
                f"Connection: keep-alive\r\n"
                f"Upgrade-Insecure-Requests: 1\r\n\r\n"
            )
            
            # Send HTTP request
            sock.send(http_request.encode())
            
            # Try to receive response (but don't wait too long)
            try:
                sock.recv(1024)
            except:
                pass
                
            # Close the socket
            sock.close()
        except:
            # Most connections will fail, which is expected
            pass

    def _generate_https_traffic(self, target_ip: str):
        """Generate HTTPS traffic to target IP"""
        try:
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            # Connect to port 443
            sock.connect((target_ip, 443))
            
            # Send TLS Client Hello (simplified)
            # This is a basic representation - real TLS is more complex
            tls_header = bytes([
                0x16,  # Content Type: Handshake
                0x03, 0x01,  # Version: TLS 1.0
                0x00, 0x2f,  # Length: 47 bytes
            ])
            
            # Send the header
            sock.send(tls_header)
            
            # Close the socket
            sock.close()
        except:
            # Most connections will fail, which is expected
            pass

    def traceroute(self, ip: str, protocol: str = "icmp"):
        """Perform traceroute to an IP address"""
        if not self.validate_ip(ip) and not self.validate_ipv6(ip):
            print(f"{Colors.RED}Invalid IP address format{Colors.END}")
            return
            
        print(f"{Colors.GREEN}Starting {protocol.upper()} traceroute to {ip}{Colors.END}")
        self.log_operation("TRACEROUTE", f"IP: {ip}, Protocol: {protocol}")
        
        try:
            if protocol.lower() == "tcp":
                result = subprocess.run(
                    ["traceroute", "-T", "-w", "1", "-q", "1", ip],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            elif protocol.lower() == "udp":
                result = subprocess.run(
                    ["traceroute", "-U", "-w", "1", "-q", "1", ip],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:  # ICMP
                result = subprocess.run(
                    ["traceroute", "-w", "1", "-q", "1", ip],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
            print(f"{Colors.CYAN}{result.stdout}{Colors.END}")
            if result.stderr:
                print(f"{Colors.RED}{result.stderr}{Colors.END}")
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}Traceroute timed out{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Error performing traceroute: {e}{Colors.END}")

    def scan_ports(self, ip: str, deep: bool = False):
        """Scan ports on a target IP"""
        if not self.validate_ip(ip) and not self.validate_ipv6(ip):
            print(f"{Colors.RED}Invalid IP address format{Colors.END}")
            return
            
        port_range = range(1, 65536) if deep else range(1, 1001)
        print(f"{Colors.GREEN}Starting {'deep ' if deep else ''}port scan on {ip}{Colors.END}")
        print(f"{Colors.GREEN}Scanning {len(port_range)} ports...{Colors.END}")
        
        self.log_operation("PORT_SCAN", f"IP: {ip}, Deep: {deep}, Ports: {len(port_range)}")
        
        open_ports = []
        start_time = time.time()
        
        # Use thread pool for faster scanning
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._check_port, ip, port): port for port in port_range}
            
            for i, future in enumerate(futures):
                try:
                    port, is_open = future.result(timeout=self.config['scan_timeout'])
                    if is_open:
                        open_ports.append(port)
                        print(f"{Colors.GREEN}Port {port} is open{Colors.END}")
                        
                    # Display progress every 100 ports
                    if (i + 1) % 100 == 0:
                        elapsed = time.time() - start_time
                        print(f"{Colors.DARK_GREEN}Scanned {i+1} ports | Elapsed: {elapsed:.1f}s | Open ports: {len(open_ports)}{Colors.END}")
                        
                except Exception as e:
                    pass
                    
        elapsed = time.time() - start_time
        print(f"{Colors.GREEN}Scan completed in {elapsed:.1f} seconds{Colors.END}")
        print(f"{Colors.GREEN}Open ports: {sorted(open_ports)}{Colors.END}")
        
        self.log_operation("PORT_SCAN_COMPLETE", 
                          f"IP: {ip}, Open ports: {len(open_ports)}, Time: {elapsed:.1f}s")

    def _check_port(self, ip: str, port: int) -> Tuple[int, bool]:
        """Check if a port is open on the target IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config['scan_timeout'])
            result = sock.connect_ex((ip, port))
            sock.close()
            return port, result == 0
        except:
            return port, False

    def test_connection(self):
        """Test network connectivity"""
        print(f"{Colors.GREEN}Testing network connectivity...{Colors.END}")
        
        test_ips = ["8.8.8.8", "1.1.1.1", "google.com"]
        all_successful = True
        
        for test_ip in test_ips:
            success, response_time = self.ping_ip(test_ip)
            status = f"{Colors.GREEN}SUCCESS{Colors.END}" if success else f"{Colors.RED}FAILED{Colors.END}"
            print(f"Ping {test_ip}: {status} ({response_time}ms)")
            
            if not success:
                all_successful = False
                
        if all_successful:
            print(f"{Colors.GREEN}All connectivity tests passed{Colors.END}")
        else:
            print(f"{Colors.RED}Some connectivity tests failed{Colors.END}")

    def dns_lookup(self, domain: str):
        """Perform DNS lookup for a domain"""
        print(f"{Colors.GREEN}Performing DNS lookup for {domain}{Colors.END}")
        self.log_operation("DNS_LOOKUP", f"Domain: {domain}")
        
        try:
            # A record
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                print(f"{Colors.CYAN}A Records:{Colors.END}")
                for record in a_records:
                    print(f"  {record.address}")
            except:
                print(f"{Colors.RED}No A records found{Colors.END}")
                
            # AAAA record (IPv6)
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                print(f"{Colors.CYAN}AAAA Records:{Colors.END}")
                for record in aaaa_records:
                    print(f"  {record.address}")
            except:
                print(f"{Colors.RED}No AAAA records found{Colors.END}")
                
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                print(f"{Colors.CYAN}MX Records:{Colors.END}")
                for record in mx_records:
                    print(f"  {record.preference} {record.exchange}")
            except:
                print(f"{Colors.RED}No MX records found{Colors.END}")
                
            # NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                print(f"{Colors.CYAN}NS Records:{Colors.END}")
                for record in ns_records:
                    print(f"  {record.target}")
            except:
                print(f"{Colors.RED}No NS records found{Colors.END}")
                
        except dns.resolver.NXDOMAIN:
            print(f"{Colors.RED}Domain does not exist{Colors.END}")
        except dns.resolver.NoAnswer:
            print(f"{Colors.RED}No DNS records found{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}DNS lookup error: {e}{Colors.END}")

    def reverse_dns(self, ip: str):
        """Perform reverse DNS lookup"""
        if not self.validate_ip(ip):
            print(f"{Colors.RED}Invalid IP address format{Colors.END}")
            return
            
        print(f"{Colors.GREEN}Performing reverse DNS lookup for {ip}{Colors.END}")
        self.log_operation("REVERSE_DNS", f"IP: {ip}")
        
        try:
            hostname, aliases, addresses = socket.gethostbyaddr(ip)
            print(f"{Colors.CYAN}Hostname: {hostname}{Colors.END}")
            if aliases:
                print(f"{Colors.CYAN}Aliases: {aliases}{Colors.END}")
            if addresses:
                print(f"{Colors.CYAN}Addresses: {addresses}{Colors.END}")
        except socket.herror:
            print(f"{Colors.RED}No reverse DNS record found{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Reverse DNS lookup error: {e}{Colors.END}")

    def whois_lookup(self, query: str):
        """Perform WHOIS lookup"""
        print(f"{Colors.GREEN}Performing WHOIS lookup for {query}{Colors.END}")
        self.log_operation("WHOIS_LOOKUP", f"Query: {query}")
        
        try:
            # Try to use system whois command
            result = subprocess.run(
                ["whois", query],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Extract relevant information
                lines = result.stdout.split('\n')
                relevant_info = []
                
                # Look for key fields
                key_fields = ['Registrar', 'Creation Date', 'Updated Date', 
                             'Expiration Date', 'Name Server', 'Status']
                
                for line in lines:
                    for field in key_fields:
                        if field.lower() in line.lower() and ':' in line:
                            relevant_info.append(line.strip())
                            break
                
                if relevant_info:
                    print(f"{Colors.CYAN}Relevant WHOIS information:{Colors.END}")
                    for info in relevant_info:
                        print(f"  {info}")
                else:
                    print(f"{Colors.CYAN}{result.stdout}{Colors.END}")
            else:
                print(f"{Colors.RED}WHOIS lookup failed{Colors.END}")
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}WHOIS lookup timed out{Colors.END}")
        except FileNotFoundError:
            print(f"{Colors.RED}WHOIS command not available{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}WHOIS lookup error: {e}{Colors.END}")

    def monitor_bandwidth(self, duration: int = 10):
        """Monitor bandwidth usage"""
        print(f"{Colors.GREEN}Monitoring bandwidth for {duration} seconds...{Colors.END}")
        print(f"{Colors.GREEN}Press Ctrl+C to stop early{Colors.END}")
        
        try:
            # Get initial network stats
            net_io_start = psutil.net_io_counters()
            start_time = time.time()
            
            while time.time() - start_time < duration:
                time.sleep(1)
                net_io_current = psutil.net_io_counters()
                
                # Calculate rates
                elapsed = time.time() - start_time
                bytes_sent = net_io_current.bytes_sent - net_io_start.bytes_sent
                bytes_recv = net_io_current.bytes_recv - net_io_start.bytes_recv
                
                # Convert to bits per second
                bps_sent = (bytes_sent * 8) / elapsed
                bps_recv = (bytes_recv * 8) / elapsed
                
                # Convert to appropriate units
                if bps_sent > 1000000:
                    sent_str = f"{bps_sent / 1000000:.2f} Mbps"
                else:
                    sent_str = f"{bps_sent / 1000:.2f} Kbps"
                    
                if bps_recv > 1000000:
                    recv_str = f"{bps_recv / 1000000:.2f} Mbps"
                else:
                    recv_str = f"{bps_recv / 1000:.2f} Kbps"
                
                # Clear line and print updated stats
                sys.stdout.write('\r\033[K')
                sys.stdout.write(f"{Colors.CYAN}Upload: {sent_str} | Download: {recv_str}{Colors.END}")
                sys.stdout.flush()
                
            print(f"\n{Colors.GREEN}Bandwidth monitoring completed{Colors.END}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Bandwidth monitoring stopped{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Bandwidth monitoring error: {e}{Colors.END}")

    def config_telegram(self, key: str, value: str):
        """Configure Telegram settings"""
        if key == "token":
            self.config['telegram_token'] = value
            print(f"{Colors.GREEN}Telegram token configured{Colors.END}")
        elif key == "chat_id":
            self.config['telegram_chat_id'] = value
            print(f"{Colors.GREEN}Telegram chat ID configured{Colors.END}")
        else:
            print(f"{Colors.RED}Invalid configuration key{Colors.END}")
            
        self.log_operation("CONFIG_TELEGRAM", f"{key}: {value}")

    def send_telegram_message(self, message: str):
        """Send a message via Telegram"""
        if not self.config['telegram_token'] or not self.config['telegram_chat_id']:
            print(f"{Colors.RED}Telegram not configured. Set token and chat ID first.{Colors.END}")
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
            data = {
                "chat_id": self.config['telegram_chat_id'],
                "text": message
            }
            
            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                print(f"{Colors.GREEN}Message sent to Telegram{Colors.END}")
                return True
            else:
                print(f"{Colors.RED}Failed to send message: {response.text}{Colors.END}")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}Error sending Telegram message: {e}{Colors.END}")
            return False

    def export_data(self):
        """Export data to Telegram"""
        if not self.operation_log:
            print(f"{Colors.YELLOW}No data to export{Colors.END}")
            return
            
        # Prepare the message (Telegram has a 4096 character limit)
        message = "Cyber Security Tool Export\n\n"
        message += "\n".join(self.operation_log[-20:])  # Last 20 entries
        
        if len(message) > 4000:
            message = message[:4000] + "\n... (truncated)"
            
        if self.send_telegram_message(message):
            print(f"{Colors.GREEN}Data exported to Telegram{Colors.END}")
            self.log_operation("EXPORT_DATA", "To Telegram")

    def show_status(self):
        """Show current tool status"""
        print(f"{Colors.BOLD}{Colors.LIGHT_GREEN}Cyber Security Tool Status{Colors.END}")
        print(f"{Colors.GREEN}Monitoring: {len(self.monitored_ips)} IPs{Colors.END}")
        print(f"{Colors.GREEN}Traffic Generation: {'Active' if self.traffic_generation else 'Inactive'}{Colors.END}")
        print(f"{Colors.GREEN}Telegram: {'Configured' if self.config['telegram_token'] and self.config['telegram_chat_id'] else 'Not Configured'}{Colors.END}")
        print(f"{Colors.GREEN}Log Entries: {len(self.operation_log)}{Colors.END}")

    def view_log(self):
        """View operation log"""
        if not self.operation_log:
            print(f"{Colors.YELLOW}No log entries{Colors.END}")
            return
            
        print(f"{Colors.BOLD}{Colors.LIGHT_GREEN}Operation Log{Colors.END}")
        for entry in self.operation_log[-20:]:  # Show last 20 entries
            print(f"{Colors.DARK_GREEN}{entry}{Colors.END}")

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()

    def run_command(self, command: str):
        """Parse and execute a command"""
        parts = command.strip().split()
        if not parts:
            return
            
        cmd = parts[0].lower()
        
        try:
            if cmd == "help":
                self.print_help()
                
            elif cmd == "exit":
                self.stop_monitoring()
                print(f"{Colors.GREEN}Exiting Cyber Security Tool{Colors.END}")
                exit(0)
                
            elif cmd == "clear":
                self.clear_screen()
                
            elif cmd == "view":
                self.view_log()
                
            elif cmd == "status":
                self.show_status()
                
            elif cmd == "ping" and len(parts) >= 3:
                if parts[1].lower() == "ip":
                    ip = parts[2]
                    success, response_time = self.ping_ip(ip)
                    status = f"{Colors.GREEN}Reachable{Colors.END}" if success else f"{Colors.RED}Unreachable{Colors.END}"
                    print(f"Ping {ip}: {status} ({response_time}ms)")
                    
                elif parts[1].lower() == "ip6" and len(parts) >= 3:
                    ip = parts[2]
                    success, response_time = self.ping_ip6(ip)
                    status = f"{Colors.GREEN}Reachable{Colors.END}" if success else f"{Colors.RED}Unreachable{Colors.END}"
                    print(f"Ping {ip}: {status} ({response_time}ms)")
                    
                elif parts[1].lower() == "hostname" and len(parts) >= 3:
                    hostname = parts[2]
                    ip = self.resolve_hostname(hostname)
                    if ip:
                        success, response_time = self.ping_ip(ip)
                        status = f"{Colors.GREEN}Reachable{Colors.END}" if success else f"{Colors.RED}Unreachable{Colors.END}"
                        print(f"Ping {hostname} ({ip}): {status} ({response_time}ms)")
                    else:
                        print(f"{Colors.RED}Could not resolve hostname: {hostname}{Colors.END}")
                    
            elif cmd == "start" and len(parts) >= 4 and parts[1].lower() == "monitoring":
                if parts[2].lower() == "ip":
                    ip = parts[3]
                    self.start_monitoring_ip(ip)
                    
            elif cmd == "stop":
                self.stop_monitoring()
                
            elif cmd == "config" and len(parts) >= 4:
                if parts[1].lower() == "telegram":
                    if parts[2].lower() == "token":
                        self.config_telegram("token", parts[3])
                    elif parts[2].lower() == "chat_id":
                        self.config_telegram("chat_id", parts[3])
                        
            elif cmd == "test" and len(parts) >= 2:
                if parts[1].lower() == "message":
                    self.send_telegram_message("Test message from Cyber Security Tool")
                elif parts[1].lower() == "connection":
                    self.test_connection()
                    
            elif cmd == "add" and len(parts) >= 3:
                if parts[1].lower() == "ip":
                    ip = parts[2]
                    if self.validate_ip(ip) or self.validate_ipv6(ip):
                        self.ip_list.add(ip)
                        print(f"{Colors.GREEN}Added IP: {ip}{Colors.END}")
                    else:
                        print(f"{Colors.RED}Invalid IP address{Colors.END}")
                        
            elif cmd == "remove" and len(parts) >= 3:
                if parts[1].lower() == "ip":
                    ip = parts[2]
                    if ip in self.ip_list:
                        self.ip_list.remove(ip)
                        print(f"{Colors.GREEN}Removed IP: {ip}{Colors.END}")
                    else:
                        print(f"{Colors.YELLOW}IP not in list{Colors.END}")
                        
            elif cmd == "generate" and len(parts) >= 4:
                if parts[1].lower() == "traffic":
                    if len(parts) >= 5:
                        # Format: generate traffic <IP> <TYPE> <DURATION>
                        target_ip = parts[2]
                        traffic_type = parts[3]
                        duration = parts[4]
                        self.generate_traffic(target_ip, traffic_type, duration)
                    else:
                        # Format: generate traffic <TYPE> <DURATION> (to monitored IPs)
                        traffic_type = parts[2]
                        duration = parts[3]
                        self.generate_traffic_to_monitored(traffic_type, duration)
                    
            elif cmd == "traceroute" and len(parts) >= 3:
                if parts[1].lower() == "ip":
                    ip = parts[2]
                    self.traceroute(ip)
                    
            elif cmd == "tcptraceroute" and len(parts) >= 3:
                if parts[1].lower() == "ip":
                    ip = parts[2]
                    self.traceroute(ip, "tcp")
                    
            elif cmd == "udptraceroute" and len(parts) >= 3:
                if parts[1].lower() == "ip":
                    ip = parts[2]
                    self.traceroute(ip, "udp")
                    
            elif cmd == "scan" and len(parts) >= 3:
                if parts[1].lower() == "ip":
                    ip = parts[2]
                    self.scan_ports(ip)
                    
            elif cmd == "deep" and len(parts) >= 4:
                if parts[1].lower() == "scan" and parts[2].lower() == "ip":
                    ip = parts[3]
                    self.scan_ports(ip, deep=True)
                    
            elif cmd == "dns" and len(parts) >= 3:
                if parts[1].lower() == "lookup":
                    domain = parts[2]
                    self.dns_lookup(domain)
                    
            elif cmd == "reverse" and len(parts) >= 3:
                if parts[1].lower() == "dns":
                    ip = parts[2]
                    self.reverse_dns(ip)
                    
            elif cmd == "whois" and len(parts) >= 2:
                query = parts[1]
                self.whois_lookup(query)
                
            elif cmd == "bandwidth":
                duration = 10
                if len(parts) >= 2:
                    try:
                        duration = int(parts[1])
                    except ValueError:
                        pass
                self.monitor_bandwidth(duration)
                
            elif cmd == "network" and len(parts) >= 2:
                if parts[1].lower() == "info":
                    network_info = self.get_network_info()
                    if network_info:
                        print(f"{Colors.CYAN}Network Information:{Colors.END}")
                        for interface, info in network_info.items():
                            print(f"{Colors.GREEN}Interface: {interface}{Colors.END}")
                            for key, value in info.items():
                                print(f"  {key}: {value}")
                    else:
                        print(f"{Colors.RED}Could not retrieve network information{Colors.END}")
                    
            elif cmd == "export" and len(parts) >= 2:
                if parts[1].lower() == "data":
                    self.export_data()
                    
            else:
                print(f"{Colors.RED}Unknown command: {command}{Colors.END}")
                print(f"{Colors.YELLOW}Type 'help' for available commands{Colors.END}")
                
        except Exception as e:
            print(f"{Colors.RED}Error executing command: {e}{Colors.END}")

    def run(self):
        """Main run loop"""
        self.clear_screen()
        
        while True:
            try:
                command = input(f"{Colors.GREEN}cyber-tool>{Colors.END} ")
                self.run_command(command)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the tool")
            except Exception as e:
                print(f"{Colors.RED}Unexpected error: {e}{Colors.END}")

def main():
    """Main function"""
    tool = CyberSecurityTool()
    tool.run()

if __name__ == "__main__":
    main()