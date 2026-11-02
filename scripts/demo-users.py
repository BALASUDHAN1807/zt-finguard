#!/usr/bin/env python3
"""Print the generated demo users and their CURRENT authenticator codes.

For demos only. In real use each person scans their own TOTP secret into an
authenticator app (Google Authenticator, Authy, ...).
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def totp(secret: str, t: float | None = None) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = struct.pack(">Q", int((t or time.time()) // 30))
    h = hmac.new(key, counter, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


users = json.load(open(os.path.join(ROOT, "secrets", "seed_users.json")))["users"]
left = 30 - int(time.time()) % 30
print(f"{'user':12} {'role':9} {'password':18} {'code now':9} (valid ~{left}s)  TOTP secret")
for u in users:
    print(f"{u['username']:12} {u['role']:9} {u['password']:18} {totp(u['totp_secret']):9}"
          f"                {u['totp_secret']}")
print("\nCodes can be used once each. Account numbers: alice ZT1000000003, bob ZT1000000004, "
      "victim_demo ZT1000000005")
