# Port Knocking Implementation

A minimal port knocking security implementation using Python and iptables firewall rules.

## Overview

Port knocking is a security technique where a server's protected port remains closed until a client performs a specific sequence of connection attempts (knocks) on predetermined ports. Only after completing the correct sequence is access granted.

## Design Architecture

### Server Design (`knock_server.py`)

The server uses **iptables firewall rules** at the IP layer to implement port knocking, rather than listening on knock ports at the application layer.

**Key Design Decision:**

- Opened up a single protected port and applied firewall rules to enforce the knock sequence, rather than having the server listen on multiple knock ports. This allows for more efficient packet filtering and reduces the attack surface at the application layer.

- Dropped packets at the firewall level for any connection attempts that do not follow the correct knock sequence or do not follow the expected timing (10 seconds), ensuring that unauthorized access attempts never reach the application layer.

- Dropped the packets instead of rejecting them to avoid sending any response back to the client, which enhances security by not revealing the presence of the protected service. It also wastes the time of the attacker by making them wait for timeouts instead of receiving immediate feedback.

```python
# I did not use these functions in the final implementation because I directly applied 
# iptables rules in the listen_for_knocks function, but they are left here as 
# placeholders for potential future refactoring.
def open_protected_port(protected_port):
    """Open the protected port using firewall rules."""
    logging.info("TODO: Open firewall for port %s", protected_port)

# I automatically close the protectted port after 10 seconds of a successful knock using 
# the iptables rules, so this function is not used in the current implementation. 
# It is left here as a placeholder for potential future refactoring.
def close_protected_port(protected_port):
    """Close the protected port using firewall rules."""
    logging.info("TODO: Close firewall for port %s", protected_port)
```

The implementation works by:

1. **Binding to the protected port** - A Python socket listens on the specified protected port (default is 2222) for incoming connections

```python
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
```
2. **Applying iptables rules** - Firewall rules intercept packets before they reach the application layer
3. **Sequential knock validation** - Each knock port adds the source IP to a "recent" list with a time window
4. **Automatic access control** - Only IPs that complete the sequence in the right order in the right time window can access the protected port

### Firewall Rules

```python
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

    # Remove from knock3
    ["iptables", "-A", "INPUT", "-p", "tcp", "-m", "multiport", "!", "--dports", str(port1)+","+str(port2)+","+str(port3)+","+str(protected_port), "-m", "recent", "--name", "knock3", "--remove"],

    # Drop all other TCP packets
    ["iptables", "-A", "INPUT", "-p", "tcp", "-j", "DROP"]
]
```

**Time Window Enforcement:**
```python
DEFAULT_SEQUENCE_WINDOW = 10.0  # Seconds allowed to complete the sequence
```

**Applying the Rules:**
```python
# This loop runs these iptable commands inside the docker containter using the subprocess module. 
for i, rule in enumerate(rules):
    logger.info(f"DEBUG: Applying rule {i+1}: {' '.join(rule)}")
    try:
        subprocess.run(rule, check=True)
    except subprocess.CalledProcessError as e:
         logger.warning(f"DEBUG: Failed to run rule {i+1}: {e}")
```

### Main Server Loop

```python
# Here we have a while true loop that will accept any connection coming to the port 2222
# However, the iptable firewall rules we implemented will discard the packets coming 
# for port 2222 at the IP layer. It won't even reach the application (python socket) 
# layer unless the user performs port knocking and gets past the firewall rules.
     
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
```

The server continuously accepts connections, but iptables blocks all packets unless the knock sequence is completed correctly.

### Client Design (`knock_client.py`)

The client sends TCP connection attempts to each port in the sequence:

```python
def send_knock(target, port, delay):
    """Send a single knock to the target port."""
    # TODO: Choose UDP or TCP knocks based on your design.
    # Example TCP knock stub:
    try:
        with socket.create_connection((target, port), timeout=1.0):
            pass  # Connection is immediately closed after the knock
    except OSError:
        pass
    time.sleep(delay)


def perform_knock_sequence(target, sequence, delay):
    """Send the full knock sequence."""
    for port in sequence:
        send_knock(target, port, delay)
```

## Configuration

### Default Values

- **Knock Sequence:** `[1234, 5678, 9012]`
- **Protected Port:** `2222`
- **Sequence Window:** `10.0 seconds`
- **Knock Delay:** `0.3 seconds`

## Usage

### Running the Server

```bash
# With defaults as it is in the Dockerfile
python3 knock_server.py

# Custom configuration
python3 knock_server.py --sequence "1111,2222,3333" --protected-port 8080 --window 15
```

### Running the Client

```bash
# Basic knock
python3 knock_client.py --target 172.20.0.40

# Custom sequence with connection check after knocking, custom sequence but default delay
python3 knock_client.py --target 172.20.0.40 --sequence "1111,2222,3333" --check

# With custom delay but default sequence
python3 knock_client.py --target 172.20.0.40 --delay 0.5 --check
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 netcat-openbsd\
    && rm -rf /var/lib/apt/lists/*

COPY knock_server.py knock_client.py ./

EXPOSE 2222

CMD ["python3", "knock_server.py"]
```

### Building and Running

```bash
# Build image and don't do -d to see the logs in the terminal for easier debugging
docker compose up --build 

# Assuming you are inside the repo directory and once the docker containers are running
cd port_knocking
sudo docker cp demo.sh 2_network_port_knocking:/app
sudo docker cp knock_client.py 2_network_port_knocking:/app

# Then you can open shell on one of the containers. I chose the web app container
sudo docker exec -it 2_network_port_knocking_web_1 /bin/bash
apt update && apt install netcat-traditional -y
./demo.sh

```

## Demo Script

The `demo.sh` script demonstrates three scenarios:

1. **Correct knock sequence** - Successfully accesses protected port
```bash
TARGET_IP=${1:-172.20.0.40}
SEQUENCE=${2:-"1234,5678,9012"}
PROTECTED_PORT=${3:-2222}

echo "Attempting correct knock sequence: $SEQUENCE"
echo "[1/3] Attempting protected port before knocking"
nc -z -v -w 10 "$TARGET_IP" "$PROTECTED_PORT" || true

echo "[2/3] Sending knock sequence: $SEQUENCE"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE" --check

echo "[3/3] Attempting protected port after knocking"
nc -z -v -w 10 "$TARGET_IP" "$PROTECTED_PORT" || true
```
2. **Incorrect knock sequence** - Fails to access protected port (extra knock resets state)
```bash
echo "Attempting incorrect knock sequence: $SEQUENCE"
echo "[1/3] Attempting protected port before knocking"
nc -z -v -w 10 "$TARGET_IP" "$PROTECTED_PORT" || true

echo "[2/3] Sending knock sequence: $SEQUENCE"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE" --check

echo "[3/3] Attempting protected port after knocking"
nc -z -v -w 10 "$TARGET_IP" "$PROTECTED_PORT" || true
```
3. **Expired sequence** - Fails when delay between knocks exceeds the time window

```bash
echo "Attempting correct knock sequence again: 1234,5678,9012 but with delay between knocks"
SEQUENCE=${2:-"1234,5678,9012,5676"}
echo "[1/3] Attempting protected port before knocking"
nc -z -v -w 10 "$TARGET_IP" "$PROTECTED_PORT" || true

echo "[2/3] Sending knock sequence: $SEQUENCE with delay between knocks"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE" --delay 7 --check

echo "[3/3] Attempting protected port after knocking"
nc -z -v -w 10 "$TARGET_IP" "$PROTECTED_PORT" || true
```

In between the scenarios, the script waits for 15 seconds to allow any previous knock state to expire before testing the next case.

```bash
echo "Waiting for knock sequence to expire..."
sleep 15
```

## Security Features

- **Firewall-level enforcement** - Rules applied at IP layer, not application layer
- **Automatic state reset** - Wrong port attempts clear all knock lists
- **Time-bound sequences** - Must complete sequence within configured window
- **Connection dropping** - All non-knocked connections silently dropped

## Debugging

The server logs iptables rules on startup:

```python
# This prints the iptable rules inside the logging tab of the docker container 
# in docker desktop for easier debugging
logger.info("DEBUG: [VERIFICATION] Listing current iptables rules to confirm port is locked:")
subprocess.run(["iptables", "-n", "-L", "INPUT"], check=False)
```

Check Docker Desktop logs to verify firewall rules are applied correctly.

## Limitations

- Requires privileged Docker container or root access for iptables
- TCP-based knocks are detectable in network traffic
- Single concurrent knock sequence per source IP
- No encryption or authentication of knock sequence itself

## Future Improvements

Placeholder functions exist for potential refactoring:

```python
# I automatically close the protected port after 10 seconds of a successful knock 
# using the iptables rules, so this function is not used in the current implementation. 
# It is left here as a placeholder for potential future refactoring.
def close_protected_port(protected_port):
    """Close the protected port using firewall rules."""
    logging.info("TODO: Close firewall for port %s", protected_port)
```

Potential enhancements:
- UDP knock support
- Per-client port access duration
- Encrypted knock sequences
- Multiple protected services