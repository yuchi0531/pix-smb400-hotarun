#!/usr/bin/env python3
"""fanout_sub.py — fanout subscriber helper (test only)."""
import socket
import sys

host, port, service, token, out, timeout = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], float(sys.argv[6]) if len(sys.argv) > 6 else 8.0
s = socket.create_connection((host, port), timeout=5)
s.settimeout(timeout)
s.sendall(f"B61/1 SUBSCRIBE SERVICE {service} TOKEN {token}\n".encode())
resp = b""
while not resp.endswith(b"\n"):
    c = s.recv(1)
    if not c:
        print("no handshake", file=sys.stderr)
        sys.exit(1)
    resp += c
if b"OK" not in resp:
    print(f"reject: {resp!r}", file=sys.stderr)
    sys.exit(1)
s.settimeout(2.0)
with open(out, "wb") as f:
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            f.write(d)
    except socket.timeout:
        pass
print(f"fanout saved to {out}", file=sys.stderr)
