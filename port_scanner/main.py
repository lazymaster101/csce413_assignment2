#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor


def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # TODO: Create a socket
        newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TODO: Set timeout
        newSocket.settimeout(timeout)
        # TODO: Try to connect to target:port
        newSocket.connect((target, port))
        # newSocket.send(b'GET / HTTP/1.1\r\n\r\n')

        # banner = newSocket.recv(1024)
        # print("here is the banner", banner)
        # TODO: Close the socket
        newSocket.close()
        # TODO: Return True if connection successful
        return (True, port)
        # if banner:
        #     return (True, port, banner.decode('utf-8', errors="ignore").strip())
        # else:
        #     return(False, port, "Connection closed no data")
        # pass  # Remove this and implement

    except Exception as e:
        # print(e)
        return (False, port)


def scan_range(target, start_port, end_port, threads):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    open_ports = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance
    with ThreadPoolExecutor(max_workers=threads) as executor:
        ports = list(range(start_port, end_port+1))
        futures = [executor.submit(scan_port, target, port, timeout=10) for port in ports]
        
        for future in futures:
            # portAvailable, portNumber, banner = future.result()
            portAvailable, portNumber = future.result()
            if portAvailable:
                open_ports.append(portNumber)
                # print("Port", portNumber, "is available. Service running:")
            
                # print("Port", portNumber, "is not open")
    # for port in range(start_port, end_port + 1):
    #     # TODO: Scan this port
    #     portAvailable = scan_port(target, port, timeout=1.0)
    #     # TODO: If open, add to open_ports list
        
    #     # TODO: Print progress (optional)
    #     print("Finished scanning port #", port, sep="")
        # pass  # Remove this and implement

    return open_ports


def main():
    """Main function"""
    # TODO: Parse command-line arguments
    # TODO: Validate inputs
    # TODO: Call scan_range()
    # TODO: Display results

    # Example usage (you should improve this):
    if len(sys.argv) < 5:
        print("Usage: python3 -m main --target <target> --ports <startport-endport> --threads <num_threads>")
        print("Example: python3 -m main --target 172.20.0.0/24 --ports 1-10000 --threads 100")
        sys.exit(1)


    if (sys.argv[1] != "--target"):
        print("Target flag is incorrect. Use --target <target>")
        sys.exit(1)

    try:
        ipaddress.IPv4Network(sys.argv[2])
    except ValueError:
        print("IPv4 address not correctly formatted")
        sys.exit(1)

    if (sys.argv[3] != "--ports"):
        print("Ports flag is incorrect. User --ports <port range>")
        sys.exit(1)

    if (not re.search(r'^\d{1,5}-\d{1,5}$', sys.argv[4])):
        print("Port range is incorrectly specified.")
        sys.exit(1)

    if (sys.argv[5] != "--threads"):
        # print(sys.argv[4])
        print("Thread flag is incorrect. Use --threads <#threads>")
        sys.exit(1)

    if (not sys.argv[6].isdigit()):
        print("Port number cannot contain letters")
        sys.exit(1)

    target = ipaddress.IPv4Network(sys.argv[2])
    print(target.num_addresses)
    
    
    
    ports = sys.argv[4].split("-")
    
    start_port = int(ports[0])
    end_port = int(ports[1])  # Scan first 1024 ports by default
    threads = int(sys.argv[6])
    for ip in target.hosts():
        print(f"[*] Starting port scan on {ip}")

        open_ports = scan_range(ip, start_port, end_port, threads)

        print(f"\n[+] Scan complete!")
        print(f"[+] Found {len(open_ports)} open ports for {ip} are:")
        for port in open_ports:
            print(f"    Port {port}: open")


if __name__ == "__main__":
    main()
