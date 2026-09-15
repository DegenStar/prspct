"""End-to-end protocol test for prspct_local (and prspct_cuda) — no chain needed.

Feeds synthetic jobs over stdin, checks the binary's RATE/FOUND/INFO chatter and
verifies every reported hit against the independent Python keccak.

    python3 tests/test_miner.py                 # binary ./prspct_local, auto backend
    python3 tests/test_miner.py --backend cpu    # force the CPU backend
    python3 tests/test_miner.py --backend metal  # force the Metal backend
"""

import argparse
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prspct_keccak import claim_hash  # noqa: E402


class Miner:
    def __init__(self, binary, env_extra=None, args=()):
        env = dict(os.environ)
        env.pop("MINER_PRIVATE_KEY", None)     # keep the test off-chain
        env.update(env_extra or {})
        self.proc = subprocess.Popen([binary, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        self.lines = []

    def send(self, line):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def drain(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            line = self.proc.stdout.readline()
            if not line:
                break
            self.lines.append(line.rstrip("\n"))
        return self.lines

    def drain_until(self, marker, seconds):
        """Consume and discard output up to and including `marker`.

        Everything printed before a job-switch ack belongs to the previous job,
        so it must not be attributed to the new one.
        """
        end = time.time() + seconds
        while time.time() < end:
            line = self.proc.stdout.readline()
            if not line:
                break
            if marker in line:
                return True
        return False

    def stop(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def bits_to_target(bits):
    """target requiring `bits` leading zero bits in the hash (~1/2**bits odds)."""
    return (1 << (256 - bits)) - 1


def check(cond, label, detail=""):
    global FAILED
    if cond:
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label} {detail}")


FAILED = 0


def main():
    ap = argparse.ArgumentParser()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_bin = os.path.join(root, "prspct_local" + (".exe" if os.name == "nt" else ""))
    # Accept whichever native target was produced by the platform toolchain.
    if not os.path.exists(default_bin):
        for stem in ("prspct_cuda", "prspct_cpu"):
            for suffix in ((".exe", "") if os.name == "nt" else ("", ".exe")):
                cand = os.path.join(root, stem + suffix)
                if os.path.exists(cand):
                    default_bin = cand
                    break
            if os.path.exists(default_bin):
                break
    ap.add_argument("--bin", default=default_bin)
    ap.add_argument("--backend", default="auto")
    ap.add_argument("--seconds", type=float, default=7.0)
    a = ap.parse_args()

    if not os.path.exists(a.bin):
        print(f"missing binary {a.bin} — run `make` first")
        return 2

    rnd = random.Random(0xC0FFEE)
    sender = "%040x" % rnd.getrandbits(160)
    seed = bytes(rnd.getrandbits(8) for _ in range(32))
    target = bits_to_target(16)           # ~1 hit per 65536 hashes: hammers the hit path

    env = {"BACKEND": a.backend}
    if a.backend in ("cpu", "both", "auto"):
        env["CPU_THREADS"] = "4"
    print(f"binary={a.bin} backend={a.backend}")
    m = Miner(a.bin, env)

    m.send(f"JOB {seed.hex()} {sender} {target:064x}")
    m.send("TX 1 1000000000")
    check(m.drain_until("job accepted", 5.0), "job accepted")
    lines = m.drain(a.seconds)

    check(any("tx params ready" in l for l in lines), "tx params handled", lines[:6])
    check(any(l.startswith("RATE") for l in lines), "RATE reported", lines[-6:])
    found = [l for l in lines if l.startswith("FOUND")]
    check(bool(found), "found shares with easy target", lines[-8:])

    for l in found[:200]:
        _, n, h = l.split()
        nonce = int(n)
        want = claim_hash(seed, "0x" + sender, nonce)
        check(want == int(h, 16), f"hash for nonce {nonce}", f"\n    got  {h}\n    want {want:064x}")
        check(int(h, 16) < target, f"hash below target (nonce {nonce})")
        check(claim_hash(seed, "0x" + sender, nonce) < target, f"python agrees below target ({nonce})")

    # --- job switching: new seed, stricter target; stale hits must not leak through ---
    seed2 = bytes(rnd.getrandbits(8) for _ in range(32))
    target2 = bits_to_target(20)
    m.lines = []
    m.send(f"JOB {seed2.hex()} {sender} {target2:064x}")
    # everything printed before this ack belongs to the previous job
    check(m.drain_until("job accepted", 5.0), "second job accepted")
    lines2 = m.drain(a.seconds)
    found2 = [l for l in lines2 if l.startswith("FOUND")]
    check(bool(found2), "found shares after job switch", lines2[-6:])
    for l in found2[:200]:
        _, n, h = l.split()
        nonce = int(n)
        check(claim_hash(seed2, "0x" + sender, nonce) == int(h, 16),
              f"hash matches NEW seed for nonce {nonce}", f"\n    got  {h}")
        check(int(h, 16) < target2, f"hash below new target (nonce {nonce})")

    # --- STOP must halt output ---
    m.send("STOP")
    m.drain(0.7)
    m.lines = []
    quiet = m.drain(2.5)
    check(not any(l.startswith("FOUND") for l in quiet), "STOP halts mining", quiet[:5])

    # --- malformed job is rejected, not fatal ---
    m.send("JOB zz nothex 1234")
    bad = m.drain(1.0)
    check(any("bad job" in l for l in bad), "bad job rejected", bad[:5])
    check(m.proc.poll() is None, "binary survives bad input")

    m.stop()
    print(f"\n{FAILED} failures")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
