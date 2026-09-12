#!/usr/bin/env python3
"""check_tlv.py — parse TLV file and report counts (for tests, no secrets)."""
import struct
import sys

ECM_HDR = bytes([0x00, 0x00, 0x93, 0x2D, 0x1E, 0x01])
EMM_PRE = bytes([0x00, 0x00, 0x93, 0x2E])


def parse(path):
    data = open(path, "rb").read()
    pos = 0
    n = 0
    null = 0
    hc = 0
    sig = 0
    ecm = 0
    emm = 0
    mpu = {}
    mpu_clear = {}
    scr = 0
    clr = 0
    while pos + 4 <= len(data):
        if data[pos] != 0x7F:
            print(f"SYNC-ERR at {pos}: {data[pos]:02X}", file=sys.stderr)
            return None
        t = data[pos + 1]
        dl = struct.unpack_from(">H", data, pos + 2)[0]
        pl = 4 + dl
        if pos + pl > len(data):
            print(f"TRUNC at {pos}: need {pl}, have {len(data)-pos}", file=sys.stderr)
            return None
        pkt = data[pos:pos + pl]
        n += 1
        if t == 0xFF:
            null += 1
        elif t != 0x03:
            sig += 1
            if ECM_HDR in pkt:
                ecm += 1
            if EMM_PRE in pkt:
                emm += 1
        else:
            hc += 1
            if ECM_HDR in pkt:
                ecm += 1
            if EMM_PRE in pkt:
                emm += 1
            # HC parse for MPU
            if dl >= 3 and pkt[6] == 0x61 and len(pkt) >= 7 + 0x15:
                m = pkt[7:]
                if len(m) >= 0x15:
                    flags = m[0x00]
                    has_ext = bool(flags & 0x02)
                    has_pcnt = bool(flags & 0x20)
                    if has_ext and not has_pcnt:
                        mext = struct.unpack_from(">H", m, 0x10)[0]
                        enc = (m[0x14] & 0x18) >> 3
                        is_mpu = ((m[0x01] & 0x3F) == 0x00)
                        pid = struct.unpack_from(">H", m, 0x02)[0]
                        if (mext & 0x7FFF) == 0x0001 and is_mpu and enc != 0:
                            scr += 1
                            mpu[pid] = mpu.get(pid, 0) + 1
                        elif is_mpu and enc == 0:
                            pid2 = struct.unpack_from(">H", m, 0x02)[0]
                            mpu.setdefault(pid2, mpu.get(pid2, 0))
                            # clear (decrypted or plain) MPU per pid — for
                            # verifying service filtering after decrypt.
                            if (mext & 0x7FFF) == 0x0001:
                                clr += 1
                                mpu_clear[pid2] = mpu_clear.get(pid2, 0) + 1
        pos += pl
    trail = len(data) - pos
    return {"total": n, "null": null, "hc": hc, "sig": sig, "ecm": ecm,
            "emm": emm, "scr": scr, "clr": clr, "mpu": mpu,
            "mpu_clear": mpu_clear, "trail": trail, "bytes": len(data)}


def main():
    if len(sys.argv) < 2:
        print("usage: check_tlv.py <file>", file=sys.stderr)
        sys.exit(2)
    r = parse(sys.argv[1])
    if r is None:
        print("PARSE-FAIL", file=sys.stderr)
        sys.exit(1)
    print(f"total={r['total']} null={r['null']} hc={r['hc']} sig={r['sig']} "
          f"ecm={r['ecm']} emm={r['emm']} scr={r['scr']} clr={r['clr']} trail={r['trail']} bytes={r['bytes']}")
    for pid in sorted(r["mpu"]):
        print(f"mpu pid={pid} count={r['mpu'][pid]}")
    for pid in sorted(r["mpu_clear"]):
        print(f"mpu_clear pid={pid} count={r['mpu_clear'][pid]}")
    # machine-readable for shell: also dump key=value lines to stdout
    # (human lines above are enough; shell greps)


if __name__ == "__main__":
    main()
