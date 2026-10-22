#!/usr/bin/env python3
"""Data side of the CBT spike, run on the appliance (stdlib only): reads extents of a flat VMDK over
HTTPS `/folder` with Range requests in parallel and keeps a SHA-256 per 1 MiB block in a JSON file.

  cbt_read.py URL NETRC EXTENTS.json BLOCKS.json [THREADS]
  cbt_read.py /dev/sdX - EXTENTS.json BLOCKS.json [THREADS]   (hot-add: the disk on a proxy VM)

EXTENTS.json is the output of esxi_cbt.py snap. The extents ("extents") are read (widened to whole
blocks) and their block hashes merged into BLOCKS.json. With "allocated" in EXTENTS.json differing from
"extents" (an incremental), the merged map is then checked against a full read of every allocated
block: a mismatch means CBT missed a change. Prints one JSON line: bytes, seconds, MB/s, mismatches.
"""
import concurrent.futures
import hashlib
import json
import netrc
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

BLOCK = 1 << 20


def blocks(extents):
    out = set()
    for off, n in extents:
        out.update(range(off // BLOCK, (off + n + BLOCK - 1) // BLOCK))
    return sorted(out)


def runs(bs):
    """Consecutive blocks as [first, count], at most 64 blocks per request."""
    out = []
    for b in bs:
        if out and out[-1][0] + out[-1][1] == b and out[-1][1] < 64:
            out[-1][1] += 1
        else:
            out.append([b, 1])
    return out


def main():
    url, rc, ext_file, map_file = sys.argv[1:5]
    threads = int(sys.argv[5]) if len(sys.argv) > 5 else 4
    if url.startswith("/"):
        fd = os.open(url, os.O_RDONLY)

        def get(first, count):
            return os.pread(fd, count * BLOCK, first * BLOCK)

    else:
        host = urllib.parse.urlparse(url).hostname
        user, _, pw = netrc.netrc(rc).authenticators(host)
        ctx = ssl._create_unverified_context()
        pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pm.add_password(None, url, user, pw)
        opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(pm), urllib.request.HTTPSHandler(context=ctx))

        def get(first, count):
            req = urllib.request.Request(url, headers={"Range": f"bytes={first * BLOCK}-{(first + count) * BLOCK - 1}"})
            with opener.open(req, timeout=120) as r:
                return r.read()

    def fetch(run):
        first, count = run
        data = get(first, count)
        return {str(first + i): hashlib.sha256(data[i * BLOCK : (i + 1) * BLOCK]).hexdigest() for i in range(count)}, len(data)

    def read_all(bs):
        got, total = {}, 0
        with concurrent.futures.ThreadPoolExecutor(threads) as pool:
            for h, n in pool.map(fetch, runs(bs)):
                got.update(h)
                total += n
        return got, total

    e = json.load(open(ext_file))
    known = json.load(open(map_file)) if os.path.exists(map_file) else {}
    t0 = time.time()
    got, total = read_all(blocks(e["extents"]))
    dt = time.time() - t0
    known.update(got)
    json.dump(known, open(map_file, "w"))
    res = {"bytes": total, "seconds": round(dt, 1), "mb_s": round(total / 1e6 / max(dt, 0.001), 1)}
    if e.get("allocated") and e["allocated"] != e["extents"]:
        t0 = time.time()
        full, n = read_all(blocks(e["allocated"]))
        res["full_bytes"], res["full_seconds"] = n, round(time.time() - t0, 1)
        res["mismatches"] = sum(1 for b, h in full.items() if known.get(b) != h)
    print(json.dumps(res))


if __name__ == "__main__":
    main()
