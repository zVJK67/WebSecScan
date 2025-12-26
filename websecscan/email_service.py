import subprocess
import sys
import socket
import time
import os


def is_port_open(port=5000, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


def start_email_server():
    if is_port_open():
        return

    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_CONSOLE

    subprocess.Popen(
        [sys.executable, "-m", "websecscan.email_server"],
        creationflags=creationflags,
    )

    # Wait until Flask is actually listening
    for _ in range(10):
        if is_port_open():
            return
        time.sleep(0.5)

    print("[ERROR] Email server failed to start")
