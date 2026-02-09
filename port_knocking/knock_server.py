#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import subprocess
import sys 

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


# I did not use these functions in the final implementation because I directly applied iptables rules in the listen_for_knocks function, 
# but they are left here as placeholders for potential future refactoring.
def open_protected_port(protected_port):
    """Open the protected port using firewall rules."""
    logging.info("TODO: Open firewall for port %s", protected_port)

# I automatically close the protectted port after 10 seconds of a successful knock using the iptables rules, so this function is not used in the current implementation. 
# It is left here as a placeholder for potential future refactoring.
def close_protected_port(protected_port):
    """Close the protected port using firewall rules."""
    logging.info("TODO: Close firewall for port %s", protected_port)


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)
    
    logger.info(f"DEBUG: Attempting to bind socket to 0.0.0.0:{protected_port}")
    try:
        ourSocket = socket.socket()
        ourSocket.bind(("0.0.0.0", protected_port))
        ourSocket.listen()
        
        if ourSocket.fileno() != -1:
            bound_ip, bound_port = ourSocket.getsockname()
            logger.info(f"DEBUG: [SUCCESS] Socket is active (fd={ourSocket.fileno()}).")
            logger.info(f"DEBUG: [SUCCESS] Socket is listening on {bound_ip}:{bound_port}")
        else:
            logger.warning("DEBUG: [FAILURE] Socket creation failed (invalid file descriptor).")
            return

    except Exception as e:
        logger.error(f"DEBUG: Failed to bind socket: {e}", exc_info=True)
        return

    port1 = sequence[0]
    port2 = sequence[1]
    port3 = sequence[2]

    """
    
    Below are the rules I applied for the iptable firewall.
    The first rule sets up the first knock port (port1) to add the source IP to a recent list named "knock1" and drop the packet.
    The second rule checks for the second knock port (port2) and verifies that the source IP is in the "knock1" list within the last (window_seconds) seconds, then adds it to a new list "knock2" and drops the packet.
    The third rule checks for the third knock port (port3) and verifies that the source IP is in the "knock2" list within the last (window_seconds) seconds, then adds it to a new list "knock3" and drops the packet.
    The fourth rule checks for the protected port (protected_port) and verifies that the source IP is in the "knock3" list within the last (window_seconds) seconds, then accepts the connection.
    The next three rules remove the source IP from all knock lists if it tries to access any port that is not part of the knock sequence or the protected port, effectively resetting the knocking process.
    The final rule drops any packet that does not match the previous rules, ensuring that only properly knocked connections can access the protected port.    
    """
    rules = [
    ["iptables","-A","INPUT","-p","tcp","--dport",str(port1),
     "-m","recent","--name","knock1","--set","-j","DROP"],
    
    ["iptables","-A","INPUT","-p","tcp","--dport",str(port2),
     "-m","recent","--name","knock1","--rcheck","--seconds",str(int(window_seconds)),
     "-m","recent","--name","knock2","--set","-j","DROP"],

    ["iptables","-A","INPUT","-p","tcp","--dport",str(port3),
     "-m","recent","--name","knock2","--rcheck","--seconds",str(int(window_seconds)),
     "-m","recent","--name","knock3","--set","-j","DROP"],

    ["iptables","-A","INPUT","-p","tcp","--dport",str(protected_port),
     "-m","recent","--name","knock3","--rcheck","--seconds",str(int(window_seconds)), "-j","ACCEPT"],
    
# Remove from knock1
["iptables", "-A", "INPUT", "-p", "tcp", "-m", "multiport", "!", "--dports", str(port1)+","+str(port2)+","+str(port3)+","+str(protected_port), "-m", "recent", "--name", "knock1", "--remove"],

# Remove from knock2
["iptables", "-A", "INPUT", "-p", "tcp", "-m", "multiport", "!", "--dports", str(port1)+","+str(port2)+","+str(port3)+","+str(protected_port), "-m", "recent", "--name", "knock2", "--remove"],

["iptables", "-A", "INPUT", "-p", "tcp", "-m", "multiport", "!", "--dports", str(port1)+","+str(port2)+","+str(port3)+","+str(protected_port), "-m", "recent", "--name", "knock3", "--remove"],

# # Drop the packet
# ["iptables", "-A", "INPUT", "-p", "tcp", "-m", "multiport", "!", "--dports", str(port1)+","+str(port2)+","+str(port3)+","+str(protected_port), "-j", "DROP"]

["iptables", "-A", "INPUT", "-p", "tcp", "-j", "DROP"]

]

    logger.info(f"DEBUG: Applying {len(rules)} iptables rules...")


    # This loop runs these iptable commands inside the docker containter using the subprocess module. 
    for i, rule in enumerate(rules):
        logger.info(f"DEBUG: Applying rule {i+1}: {' '.join(rule)}")
        try:
            subprocess.run(rule, check=True)
        except subprocess.CalledProcessError as e:
             logger.warning(f"DEBUG: Failed to run rule {i+1}: {e}")

    # This prints the iptable rules inside the logging tab of the docker container in docker desktop for easier debugging
    logger.info("DEBUG: [VERIFICATION] Listing current iptables rules to confirm port is locked:")
    subprocess.run(["iptables", "-n", "-L", "INPUT"], check=False)

    logger.info("DEBUG: Rules applied. Entering main loop...")

    # Here we have a while true loop that will accept any connection coming to the port 2222
    # However, the iptable firewall rules we implemented will discard the packets coming for port 2222 at the IP layer. 
    # It won't even reach the application (python socket) layer unless the user performs port knocking and gets past the firewall rules.
     
    while True:
        logger.info("DEBUG: Waiting for connection (accept)...")
        try:
            conn, addr = ourSocket.accept()
            logger.info(f"DEBUG: [+] Connection accepted from: {addr}")
            conn.sendall(b"You have successfully knocked!\n")
            conn.close()
            logger.info("DEBUG: Connection closed.")
        except Exception as e:
            logger.warning(f"DEBUG: Error in accept loop: {e}")


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