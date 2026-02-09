#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import datetime
import logging
import os
import socket
import time
import paramiko
from paramiko import RSAKey
from paramiko.server import ServerInterface
import threading

HOST = "0.0.0.0"
PORT = 22
filesystem = {
    "/": ["bin", "etc", "home"],
    "/home": ["ubuntu"],
    "/home/ubuntu": [".bashrc", "notes.txt"],
    "/bin": ["ls", "cat", "echo"],
    "/etc": ["passwd", "shadow"]
}

# Generate host key (or load one)
host_key = RSAKey.generate(2048)
LOG_PATH = "/app/logs/honeypot.log"


def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )

COMMON_USERS = ["root", "ubuntu", "admin", "user", "test"]

COMMON_PASSWORDS = [
    "root",
    "admin",
    "password",
    "123456",
    "ubuntu",
    "toor",
    "qwerty"
]

class Honeypot(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    # Called when client tries username/password
    def check_auth_password(self, username, password):
        print(f"[LOGIN] {username}:{password}")

        if username in COMMON_USERS and password in COMMON_PASSWORDS:
            return paramiko.AUTH_SUCCESSFUL

        time.sleep(0.5)
        return paramiko.AUTH_FAILED

    # Allow shell requests
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


def normalize(path):
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") if path != "/" else "/"

def log(cmd):
    with open(LOG_PATH, "a") as f:
        f.write(f"{datetime.datetime.now()} :: {cmd}\n")


def handle_client(client):

    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)

    server = Honeypot()

    transport.start_server(server=server)

    chan = transport.accept(20)

    if chan is None:
        return

    user = "ubuntu"
    cwd = "/home/ubuntu"

    chan.send(b"Welcome to Ubuntu 20.04 LTS\r\n")
    
    while True:
        chan.send(f"{user}@host:{cwd}$ ".encode())
        data = chan.recv(1024)
        if not data:
            break

        cmd = data.decode().strip()
        log(cmd)

        if cmd == "exit":
            break

        elif cmd == "pwd":
            chan.send((cwd + "\r\n").encode())

        elif cmd == "whoami":
            chan.send(b"root\r\n")

        elif cmd == "uname -a":
            chan.send(b"Linux host 5.15.0-86-generic #96-Ubuntu SMP x86_64 GNU/Linux\r\n")

        elif cmd.startswith("ls"):
            path = cwd
            parts = cmd.split()

            if len(parts) > 1:
                path = normalize(parts[1])

            if path in filesystem:
                chan.send(("  ".join(filesystem[path]) + "\r\n").encode())
            else:
                chan.send(b"No such file or directory\r\n")

        elif cmd.startswith("cd"):
            parts = cmd.split()

            if len(parts) == 1:
                cwd = "/home/ubuntu"
            else:
                new = normalize(parts[1])

                if new in filesystem:
                    cwd = new
                else:
                    chan.send(b"No such directory\r\n")

        else:
            chan.send(b"command not found\r\n")

    chan.close()
    transport.close()


def run_honeypot():
    logger = logging.getLogger("Honeypot")
    logger.info("Honeypot starter template running.")
    logger.info("TODO: Implement protocol simulation, logging, and alerting.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(100)

    print(f"[*] Honeypot listening on {PORT}")

    while True:
        client, addr = sock.accept()
        print(f"[+] Connection from {addr}")
        handle_client(client)


if __name__ == "__main__":
    setup_logging()
    run_honeypot()
