#!/usr/bin/env python3
"""gen_tlv.py — synthetic TLV generator for local tests (no secrets).

Creates encrypted-raw-TLV-like streams using the SAME mock Ks derivation as
acasd --mock, so b61dec_worker/b61_net_server (mock) can decrypt them.
ECM bytes are synthetic incremental patterns, NOT real broadcast data.

Mock derivation (must match src/acasd.c mock_ks):
  kcl = SHA256(b"B61-MOCK-KCL-v1")
  h   = SHA256(kcl + ecm[4:27])   # ecm = ECM data starting at 93 2D 1E 01
  odd, even = h[:16], h[16:]

MMTP layout mirrors b61dec.c expectations (flags/ext/mext/enc).
"""
import argparse
import hashlib
import os
import struct
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

ECM_HDR = bytes([0x00, 0x00, 0x93, 0x2D, 0x1E, 0x01])
EMM_PREFIX = bytes([0x00, 0x00, 0x93, 0x2E])


def mock_keys(ecm: bytes):
    kcl = hashlib.sha256(b"B61-MOCK-KCL-v1").digest()
    part = bytearray(23)
    if len(ecm) >= 4 + 23:
        part[:] = ecm[4:27]
    elif len(ecm) > 4:
        part[:len(ecm) - 4] = ecm[4:]
    h = hashlib.sha256(kcl + bytes(part)).digest()
    return h[:16], h[16:]


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography lib required for encryption")
    assert HAVE_CRYPTO
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as _algos
    from cryptography.hazmat.primitives.ciphers import modes as _modes
    c = _Cipher(_algos.AES(key), _modes.CTR(iv))
    e = c.encryptor()
    return e.update(data) + e.finalize()


def tlv_pkt(ptype: int, payload: bytes) -> bytes:
    return struct.pack(">BBH", 0x7F, ptype, len(payload)) + payload


def null_pkt() -> bytes:
    return bytes([0x7F, 0xFF, 0x00, 0x00])


def signal_pkt(payload: bytes = b"HELLO-SI") -> bytes:
    # non-HC TLV (kept as NTP/TLV-SI/CAT etc.)
    return tlv_pkt(0x01, payload)


def ecm_tlv(ecm: bytes, prefix_len: int = 10) -> bytes:
    # non-HC TLV carrying ECM pattern (always kept)
    rnd = os.urandom(prefix_len) if prefix_len else b""
    data = bytes(rnd) + b"\x00\x00" + bytes(ecm)
    return tlv_pkt(0x01, data)


def make_ecm(seed: int, elen: int = 32) -> bytes:
    # ECM data starting at 93 2D 1E 01 (elen bytes)
    assert elen >= 27
    out = bytearray([0x93, 0x2D, 0x1E, 0x01])
    for k in range(elen - 4):
        out.append((seed + k) & 0xFF)
    return bytes(out)


def emm_tlv() -> bytes:
    return tlv_pkt(0x01, b"\x00" * 8 + EMM_PREFIX + b"\x11\x22\x33\x44")


def hc_mpu(pkt_id: int, seq: int, payload: bytes, enc_flag: int,
           odd=None, even=None) -> bytes:
    """Build HC NoComp scrambled/unscrambled MPU. payload = cleartext MPU payload
    (the part after 8B clear MPU header). If enc_flag != 0, encrypt with mock keys."""
    assert enc_flag in (0, 2, 3)
    # MMTP 22B header
    m = bytearray(22)
    m[0x00] = 0x02  # flags: has_ext
    m[0x01] = 0x00  # type MPU
    struct.pack_into(">H", m, 0x02, pkt_id & 0xFFFF)
    struct.pack_into(">I", m, 0x08, seq & 0xFFFFFFFF)
    struct.pack_into(">H", m, 0x0E, 6)  # ext_len
    struct.pack_into(">H", m, 0x10, 0x0001)  # mext
    m[0x14] = (enc_flag << 3) & 0x18
    m[0x15] = 0x00
    clear8 = b"\xAA" * 8
    data_part = bytes(payload)
    if enc_flag != 0:
        if odd is None or even is None:
            raise ValueError("keys required for scrambled")
        key = odd if enc_flag == 3 else even
        iv = struct.pack(">H", pkt_id & 0xFFFF) + struct.pack(">I", seq & 0xFFFFFFFF) + b"\x00" * 10
        data_part = aes_ctr(key, iv, bytes(payload))
    mmtp = bytes(m) + clear8 + data_part
    hc = bytes([0x00, 0x00, 0x61]) + mmtp
    return tlv_pkt(0x03, hc)


def hc_signal_unscrambled() -> bytes:
    # HC but enc NONE (kept as signaling)
    m = bytearray(22)
    m[0x00] = 0x02
    m[0x01] = 0x00
    struct.pack_into(">H", m, 0x02, 0x1234)
    struct.pack_into(">I", m, 0x08, 1)
    struct.pack_into(">H", m, 0x0E, 6)
    struct.pack_into(">H", m, 0x10, 0x0001)
    m[0x14] = 0x00
    mmtp = bytes(m) + b"\xBB" * 16
    return tlv_pkt(0x03, bytes([0x00, 0x00, 0x61]) + mmtp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", default="mixed",
                    choices=["mixed", "boundary", "filter", "roundtrip", "eof"])
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--service", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    out = []
    if args.mode == "boundary":
        # random sizes/types, all pass-through (unscrambled + null + signal)
        import random
        rnd = random.Random(args.seed)
        for k in range(args.count):
            r = rnd.randrange(4)
            if r == 0:
                out.append(null_pkt())
            elif r == 1:
                out.append(signal_pkt(os.urandom(rnd.randrange(1, 200))))
            elif r == 2:
                out.append(hc_signal_unscrambled())
            else:
                # unscrambled MPU
                out.append(hc_mpu(100 + (k % 3), k, os.urandom(64), 0))
    elif args.mode == "filter":
        # service A (keep) + service B (drop) + ECM + SI + EMM
        svc = args.service
        other = svc + 100
        ecm = make_ecm(args.seed)
        odd, even = mock_keys(ecm)
        out.append(signal_pkt(b"NTP/SI-KEEP"))
        out.append(ecm_tlv(ecm))
        for k in range(args.count):
            out.append(hc_mpu(svc, k, bytes([k & 0xFF]) * 64, 3, odd, even))
            out.append(hc_mpu(other, k, bytes([(k + 1) & 0xFF]) * 64, 3, odd, even))
        out.append(emm_tlv())
        out.append(null_pkt())
    elif args.mode == "roundtrip":
        ecm = make_ecm(args.seed)
        odd, even = mock_keys(ecm)
        out.append(signal_pkt(b"ROUNDTRIP-SI"))
        out.append(ecm_tlv(ecm))
        for k in range(args.count):
            flag = 3 if (k % 2 == 0) else 2
            key = odd if flag == 3 else even
            # payload deterministic for verification
            payload = bytes([(k + j) & 0xFF for j in range(64)])
            out.append(hc_mpu(args.service, k, payload, flag, odd, even))
        out.append(null_pkt())
    elif args.mode == "eof":
        ecm = make_ecm(args.seed)
        odd, even = mock_keys(ecm)
        out.append(signal_pkt(b"EOF-SI"))
        out.append(ecm_tlv(ecm))
        for k in range(5):
            out.append(hc_mpu(args.service, k, bytes([k]) * 32, 3, odd, even))
        out.append(null_pkt())
    else:  # mixed
        ecm = make_ecm(args.seed)
        odd, even = mock_keys(ecm)
        out.append(signal_pkt(b"MIXED-SI"))
        out.append(ecm_tlv(ecm))
        for k in range(args.count):
            out.append(hc_mpu(args.service, k, bytes([k & 0xFF]) * 48, 3, odd, even))
            if k % 5 == 0:
                out.append(signal_pkt(b"SI-%d" % k))

    with open(args.out, "wb") as f:
        for p in out:
            f.write(p)
    print(f"wrote {len(out)} packets to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
