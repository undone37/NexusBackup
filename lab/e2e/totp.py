#!/usr/bin/env python3
"""totp.py SECRET_B32 [offset_steps]  -> current RFC 6238 code (SHA-1, 6 digits, 30 s).
totp.py --new                       -> new random base32 secret (160 bit).
Stdlib only (matches catalog::auth)."""
import base64, hashlib, hmac, os, struct, sys, time

if sys.argv[1] == "--new":
    print(base64.b32encode(os.urandom(20)).decode())
    sys.exit()
key = base64.b32decode(sys.argv[1].upper() + "=" * (-len(sys.argv[1]) % 8))
step = int(time.time()) // 30 + (int(sys.argv[2]) if len(sys.argv) > 2 else 0)
h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
o = h[-1] & 0x0F
print("%06d" % ((struct.unpack(">I", h[o : o + 4])[0] & 0x7FFFFFFF) % 1000000))
