#!/usr/bin/env python3

import argparse
from datetime import datetime
import platform
import sys
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list, get_if_addr


def parse_http_payload(payload):
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        lines = payload_str.split('\r\n')
        
        valid_methods = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'}
        
        if not lines or len(lines[0].split()) < 3:
            return None, None, None, None
        
        request_line = lines[0].split()
        method = request_line[0]
        
        if method not in valid_methods:
            return None, None, None, None
        
        full_url = request_line[1]
        
        if '?' in full_url:
            path, params_str = full_url.split('?', 1)
            params = dict(param.split('=') for param in params_str.split('&') if '=' in param)
        else:
            path = full_url
            params = {}
        
        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        
        return method, full_url, params, headers
    except Exception:
        return None, None, None, None


def packet_callback(search_string=None):
    def process_packet(packet):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = f"[{timestamp}] "
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            summary += f"{src_ip} -> {dst_ip} "
            
            if TCP in packet:
                proto = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                summary += f"{proto} {src_port}->{dst_port}"
                
                if Raw in packet:
                    payload = packet[Raw].load
                    if dst_port == 80 or src_port == 80:
                        method, full_url, params, headers = parse_http_payload(payload)
                        if method:
                            summary += f"\n  Method: {method}"
                            summary += f"\n  Full URL: {full_url}"
                            summary += f"\n  Parameters: {params}"
                            summary += f"\n  Headers: {headers}"
                        else:
                            payload_str = payload.decode('utf-8', errors='ignore')
                            summary += f"\n  Payload: {payload_str[:50]}..." if len(payload_str) > 50 else f"\n  Payload: {payload_str}"
                    elif dst_port == 443 or src_port == 443:
                        summary += "\n  Payload: [Encrypted HTTPS]"
                    else:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        summary += f"\n  Payload: {payload_str[:50]}..." if len(payload_str) > 50 else f"\n  Payload: {payload_str}"
                    
                    if search_string:
                        payload_str = payload.decode('utf-8', errors='ignore').lower()
                        if search_string.lower() in payload_str:
                            print(summary)
                    else:
                        print(summary)
                else:
                    if not search_string:
                        print(summary)
            elif UDP in packet:
                proto = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                summary += f"{proto} {src_port}->{dst_port}"
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    summary += f"\n  Payload: {payload[:50]}..." if len(payload) > 50 else f"\n  Payload: {payload}"
                    if search_string and search_string.lower() in payload.lower():
                        print(summary)
                    elif not search_string:
                        print(summary)
                else:
                    if not search_string:
                        print(summary)
            else:
                proto = "Other"
                summary += f"{proto}"
                if not search_string:
                    print(summary)
        elif not search_string:
            print(f"{summary} {packet.summary()}")

    return process_packet


def get_interface_ip(iface):
    try:
        ip = get_if_addr(iface)
        return ip if ip != "0.0.0.0" else "No IP"
    except Exception:
        return "No IP"


def get_valid_interface(default_iface):
    available_interfaces = get_if_list()
    is_windows = platform.system() == "Windows"

    if default_iface in available_interfaces:
        return default_iface
    
    print(f"Interface '{default_iface}' not found.")
    print("Available interfaces:")
    for i, iface in enumerate(available_interfaces, 1):
        if is_windows:
            ip = get_interface_ip(iface)
            print(f"{i}. {iface} (IP: {ip})")
        else:
            print(f"{i}. {iface}")
    
    while True:
        try:
            choice = int(input("Select an interface (number): "))
            if 1 <= choice <= len(available_interfaces):
                return available_interfaces[choice - 1]
            else:
                print(f"Please enter a number between 1 and {len(available_interfaces)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def start_monitoring(interface, search_string=None):
    is_windows = platform.system() == "Windows"
    if is_windows:
        ip = get_interface_ip(interface)
        print(f"Starting lightweight packet capture on {interface} (IP: {ip})")
    else:
        print(f"Starting lightweight packet capture on {interface}")
    print("Press Ctrl+C to stop...")
    try:
        sniff(iface=interface, prn=packet_callback(search_string), store=0)
    except PermissionError:
        print(f"Error: Please run this script with {'Administrator' if is_windows else 'sudo'} privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def print_banner():
    banner = """
    +-------------------------------------------+
    |     Network Traffic Taxi by @leddcode     |
    +-------------------------------------------+
       ______
      /|_||_\`.__
     (   _    _ _\\
     =`-(_)--(_)-'      Packet Pickup!
                        Hop in, we're sniffing!    
    """
    print(banner)


def monit():
    parser = argparse.ArgumentParser(description="Lightweight network traffic monitor")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to monitor (default: eth0)")
    parser.add_argument("-s", "--string", help="Filter packets containing this string in payload")
    args = parser.parse_args()
    interface = get_valid_interface(args.interface)
    print_banner()
    start_monitoring(interface, args.string)


if __name__ == "__main__":
    monit()