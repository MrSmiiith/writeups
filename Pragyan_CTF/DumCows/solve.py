#!/usr/bin/env python3
"""DumCows Solver - Pragyan CTF 2025
Solved by Smothy @ 0xN1umb

The cow uses a shared XOR keystream for both name and says encryption.
By sending a known name, we recover the keystream.
The says plaintext is always "moooooooooooomfT_T" (the cow's garbled voice).
Sending "FIX_COW moooooooooooomfT_T" fixes the cow and reveals the encrypted flag.
Decrypt with the same keystream at offset 0.
"""
import socket
import ssl
import base64
import time
import re

def connect():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection(('dum-cows.ctf.prgy.in', 1337), timeout=15)
    ssock = ctx.wrap_socket(sock, server_hostname='dum-cows.ctf.prgy.in')
    ssock.settimeout(15)
    return ssock

def recv_all(ssock, timeout=3):
    data = b""
    ssock.settimeout(timeout)
    while True:
        try:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            data += chunk
            ssock.settimeout(1)
        except:
            break
    return data

# Step 1: Recover keystream by sending a known name
print("[*] Connecting to recover keystream...")
ssock = connect()
recv_all(ssock)  # banner

name = b"A" * 36
ssock.sendall(name + b"\n")
time.sleep(0.5)
resp = recv_all(ssock).decode('utf-8', errors='replace')
ssock.close()

m = re.search(r'\[Name:\s*([\w+/=]+)\]\s*says:\s*([\w+/=]+)', resp)
enc_name = base64.b64decode(m.group(1))
keystream = bytes(a ^ 0x41 for a in enc_name)
print(f"[+] Recovered {len(keystream)} bytes of keystream")

# Step 2: Send FIX_COW with the cow's decrypted voice
print("[*] Sending FIX_COW command...")
time.sleep(1)
ssock = connect()
recv_all(ssock)  # banner

ssock.sendall(b"FIX_COW moooooooooooomfT_T\n")
time.sleep(1)
resp = recv_all(ssock, timeout=10).decode('utf-8', errors='replace')
ssock.close()

# Step 3: Decrypt the flag
b64_matches = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', resp)
enc_flag = base64.b64decode(b64_matches[0])
flag = bytes(a ^ b for a, b in zip(enc_flag, keystream[:len(enc_flag)]))
print(f"[+] Flag: {flag.decode()}")
