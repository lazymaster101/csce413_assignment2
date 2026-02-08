#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import subprocess
import sys # Added for flushing

DEFAULT_KNOCK_SEQUENCE = [1111, 6767, 7676]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def open_protected_port(protected_port):
    """Open the protected port using firewall rules."""
    logging.info("TODO: Open firewall for port %s", protected_port)


def close_protected_port(protected_port):
    """Close the protected port using firewall rules."""
    logging.info("TODO: Close firewall for port %s", protected_port)


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    print("DEBUG: Starting listen_for_knocks...", flush=True)
    
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)
    
    print(f"DEBUG: Attempting to bind socket to 0.0.0.0:{protected_port}", flush=True)
    try:
        ourSocket = socket.socket()
        ourSocket.bind(("0.0.0.0", 2222))
        ourSocket.listen()
        
        # --- NEW CONDITION CHECKING ---
        if ourSocket.fileno() != -1:
            bound_ip, bound_port = ourSocket.getsockname()
            print(f"DEBUG: [SUCCESS] Socket is active (fd={ourSocket.fileno()}).", flush=True)
            print(f"DEBUG: [SUCCESS] Socket is listening on {bound_ip}:{bound_port}", flush=True)
        else:
            print("DEBUG: [FAILURE] Socket creation failed (invalid file descriptor).", flush=True)
            return
        # -----------------------------

    except Exception as e:
        print(f"DEBUG: Failed to bind socket: {e}", flush=True)
        return

    rules = [
    ["iptables","-A","INPUT","-p","tcp","--dport","1111",
     "-m","recent","--name","knock1","--set","-j","DROP"],
    
    ["iptables","-A","INPUT","-p","tcp","--dport","6767",
     "-m","recent","--name","knock1","--rcheck","--seconds","30",
     "-m","recent","--name","knock2","--set","-j","DROP"],

    ["iptables","-A","INPUT","-p","tcp","--dport","7676",
     "-m","recent","--name","knock2","--rcheck","--seconds","30",
     "-m","recent","--name","knock3","--set","-j","DROP"],

    ["iptables","-A","INPUT","-p","tcp","--dport","2222",
     "-m","recent","--name","knock3","--rcheck","-j","ACCEPT"],
    
    ["iptables", "-A", "INPUT", "-j", "DROP"]
    ]

    print(f"DEBUG: Applying {len(rules)} iptables rules...", flush=True)

    for i, rule in enumerate(rules):
        print(f"DEBUG: Applying rule {i+1}: {' '.join(rule)}", flush=True)
        try:
            subprocess.run(rule, check=True)
        except subprocess.CalledProcessError as e:
             print(f"DEBUG: Failed to run rule {i+1}: {e}", flush=True)

    # --- NEW FIREWALL CHECK ---
    print("DEBUG: [VERIFICATION] Listing current iptables rules to confirm port is locked:", flush=True)
    subprocess.run(["iptables", "-n", "-L", "INPUT"], check=False)
    # --------------------------

    print("DEBUG: Rules applied. Entering main loop...", flush=True)

    while True:
        print("DEBUG: Waiting for connection (accept)...", flush=True)
        try:
            conn, addr = ourSocket.accept()
            print(f"DEBUG: [+] Connection accepted from: {addr}", flush=True)
            conn.sendall(b"You have successfully knocked!\n")
            conn.close()
            print("DEBUG: Connection closed.", flush=True)
        except Exception as e:
            print(f"DEBUG: Error in accept loop: {e}", flush=True)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    # Force standard out to be unbuffered
    sys.stdout.reconfigure(line_buffering=True)
    
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()