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
# from scapy.all import *
import socket
import sys
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import time
import argparse
import json

def scan_port(target, port, timeout=3.0, results=None):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds. Default is 3 seconds.
        file (file object): Optional file object to write results to
    Returns:
        bool: True if port is open, False otherwise
    """
    
    # Start timing the scan
    start_time = time.time()
    
    try:        
        # TODO: Create a socket
        newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TODO: Set timeout
        newSocket.settimeout(timeout)
        # TODO: Try to connect to target:port
        newSocket.connect((target, port))
    
        """
        Some services like HTTP and SSH will send a banner immediately after connection. You can read this banner to identify the service and version.
        For example, an SSH server might send something like "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2" which indicates it's running OpenSSH version 7.9p1 on Debian 10.
        Seems like in our case we are not able to discover any ports without sending any information. So we will send some garbage information and try to recieve the banner.
        """
        
        
        # newSocket.send(b'GET / HTTP/1.1\r\n\r\n')
        sent = newSocket.send(b'\r\n')
        # print("Message sent successfully", sent)
        time.sleep(0.5)
        
        # We will only receive and read the banner that way
        banner = newSocket.recv(1024)
        
        # Debugging statement
        # print("here is the banner", banner)
        # TODO: Close the socket
        newSocket.close()
        
        #Calculate elapsed time
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        # Format the result into a JSON object
        result = json.dumps({
            "target": target,
            "port": port,
            "status": "open",
            "elapsed_time": elapsed_time,
            "banner": banner.decode('utf-8', errors="ignore").strip() if banner else None
        })
        
        entry = {
            "target": target,
            "port": port,
            "status": "open",
            "elapsed_time": elapsed_time,
            "banner": banner.decode('utf-8', errors="ignore").strip() if banner else None
        }

        if results is not None:
            results.append(entry)
        
        # TODO: Return True if connection successful
        return (True, port, banner)

    except socket.timeout:
        end_time = time.time()
        elapsed_time = end_time - start_time
        entry = {
            "target": target,
            "port": port,
            "status": "closed",
            "error": "timeout",
            "elapsed_time": elapsed_time,
            "banner": None
        }

        if results is not None:
            results.append(entry)

        return (False, port, None)
    except ConnectionRefusedError:
        end_time = time.time()
        elapsed_time = end_time - start_time
        entry = {
            "target": target,
            "port": port,
            "status": "closed",
            "error": "connection refused",
            "elapsed_time": elapsed_time,
            "banner": None
        }

        if results is not None:
            results.append(entry)

        return (False, port, None)
    except OSError as e:
        end_time = time.time()
        elapsed_time = end_time - start_time
        entry = {
            "target": target,
            "port": port,
            "status": "closed",
            "error": "connection refused",
            "elapsed_time": elapsed_time,
            "banner": None
        }

        if results is not None:
            results.append(entry)

        return (False, port, None)

    except Exception as e:
        end_time = time.time()
        elapsed_time = end_time - start_time
        entry = {
            "target": target,
            "port": port,
            "status": "closed",
            "error": f"Exception: {type(e).__name__}: {e}",
            "elapsed_time": elapsed_time,
            "banner": None
        }

        if results is not None:
            results.append(entry)

        return (False, port, None)
    
    # Output formats (JSON, CSV, formatted text)

    



def scan_range(target, start_port, end_port, threads, timeout, results=None):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number
        threads (int): Number of threads to use for scanning
        timeout (float): Connection timeout in seconds. Default is 3 seconds.
        results (list): Optional list to store results instead of printing
    Returns:
        list: List of open ports
    """
    open_ports = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance
    
    """
    The below function will start up a thread pool with max_workers. A thread will be created for each port in the specified port range.
    However, the number of threads will be limited to the specified max_workers to avoid overwhelming the system. Each thread will execute the scan_port function for its assigned port.
    The threads will basically take turns.
    
    Since we are using a thread pool, we can submit all the port scan tasks at once and then wait for them to complete. The results will be collected as they finish, and we can process them accordingly.
    This also means that the scanning resuls will be printed in the order they finish, which may not be the same as the order of the ports. 
    """
    with ThreadPoolExecutor(max_workers=threads) as executor:
        ports = list(range(start_port, end_port+1))
        #  TODO: Scan this port
        futures = [executor.submit(scan_port, target, port, timeout=timeout, results=results) for port in ports]
        
        for future in futures:
            # portAvailable, portNumber, banner = future.result()
            portAvailable, portNumber, banner = future.result()
            # TODO: If open, add to open_ports list
            if portAvailable:
                open_ports.append(portNumber)
                # TODO: Print progress (optional)
                print("Port", portNumber, "is available.")
                if banner:
                    print("Banner for port", portNumber, ":", banner)
    return open_ports



def parse_args():
    
    """
    Parse command-line arguments

    Returns: Parsed arguments
    """
    
    parser = argparse.ArgumentParser(description="Port scanner service starter")
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or network (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--ports",
        required=True,
        help="Port range to scan (e.g., 1-1000)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of threads to use for scanning",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Connection timeout in seconds. Default is 3 seconds.",
    )
    return parser.parse_args()


def main():
    """Main function"""
    
    # TODO: Parse command-line arguments
    args = parse_args()
    target = args.target
    ports = args.ports
    threads = args.threads
    timeout = args.timeout


    # TODO: Validate inputs
    
    # Validate target IP address or network
    # We will use the ipaddress module to validate the target. If the target is not a valid IPv4 address or network, it will raise a ValueError which we can catch and handle accordingly.
    # It will also take care of multiple hosts in the case of a network specified in CIDR notation
    try:
        ipaddress.IPv4Network(target)
    except ValueError:
        print("IPv4 address not correctly formatted")
        sys.exit(1)

    # Validate port range
    if (not re.search(r'^\d{1,5}-\d{1,5}$', ports)):
        print("Port range is incorrectly specified.")
        sys.exit(1)

    # Validate thread number
    if (not str(threads).isdigit() or int(threads) <= 0):
        print("Thread number cannot contain letters or be negative.")
        sys.exit(1)

    
    # Create the target network object
    target = ipaddress.IPv4Network(target)
    # print(target.num_addresses)
    
    
    
    ports = ports.split("-")
    
    start_port = int(ports[0])
    end_port = int(ports[1])  # Scan first 1024 ports by default
    threads = int(threads)
    timeout = float(timeout)
    
    # Loop through hosts in the target network and scan ports
    for ip in target.hosts():
        results = []

        print(f"[*] Starting port scan on {ip}")
        # TODO: Call scan_range()

        open_ports = scan_range(str(ip), start_port, end_port, threads, timeout, results)
        
        # TODO: Display results
        # We are storing the full result in a list of dictionaries called results, which we can then write to a JSON file for each host. 
        # This way we have a complete record of the scan including open and closed ports, any errors encountered, and the banners received (if any).
        # It will contain a timestamp for each scan as well. The JSON file will be named "scan_results_<ip>.json" for each host scanned.
        with open(f"scan_results_{ip}.json", "w") as f:
            json.dump({
                f"Scan on date {time.ctime()}": results
            }, f, indent=2)

        print(f"\n[+] Scan complete!")
        print(f"[+] Found {len(open_ports)} open ports for {ip} are:")
        for port in open_ports:
            print(f"    Port {port}: open")

if __name__ == "__main__":
    main()
