"""Hashrate benchmark for prspct_local across backends (metal / cpu / auto).

Feeds an impossibly hard job so nothing but RATE lines come back.

    python3 tests/bench.py --seconds 8
"""

import argparse
import os
import random
import statistics
import subprocess
import sys
import time


def run(binary, backend, seconds, threads, extra_env=None):
    env = dict(os.environ)
    env.pop("MINER_PRIVATE_KEY", None)
    env["BACKEND"] = backend
    if threads:
        env["CPU_THREADS"] = str(threads)
    env.update(extra_env or {})
    rnd = random.Random(99)
    sender = "%040x" % rnd.getrandbits(160)
    seed = bytes(rnd.getrandbits(8) for _ in range(32))
    target = 1                                   # ~2^-256 odds: never hits
    info = []
    p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
    p.stdin.write(f"JOB {seed.hex()} {sender} {target:064x}\nTX 1 1\n")
    p.stdin.flush()
    end = time.time() + seconds
    rates = []
    while time.time() < end:
        line = p.stdout.readline()
        if not line:
            break
        line = line.rstrip("\n")
        if line.startswith("RATE"):
            rates.append(float(line.split()[1]))
        elif line.startswith("INFO") or line.startswith("ERR"):
            info.append(line)
    p.stdin.close()
    try:
        p.wait(timeout=5)
    except Exception:
        p.kill()
    return rates, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prspct_local"))
    ap.add_argument("--seconds", type=float, default=8.0)
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("--backends", default="cpu,metal,auto")
    ap.add_argument("--env", action="append", default=[], help="extra env KEY=VALUE (repeatable)")
    a = ap.parse_args()

    extra = dict(kv.split("=", 1) for kv in a.env)
    for backend in a.backends.split(","):
        rates, info = run(a.bin, backend, a.seconds, a.threads, extra)
        for l in info:
            print(f"    {l}")
        if not rates:
            print(f"{backend:6s}: no RATE reported")
            continue
        best = max(rates)
        print(f"{backend:6s}: {best/1e6:9.2f} MH/s  (samples {len(rates)}, median {statistics.median(rates)/1e6:.2f} MH/s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
