"""Portable CPU miner backend (same JOB/TX/STOP protocol as native miners)."""
import os
import sys
import threading
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prspct_keccak import keccak256

_lock = threading.Lock()
_job = None
_running = True

def mine_loop():
    nonce = 0
    count = 0
    started = time.monotonic()
    last_rate = started
    while _running:
        with _lock:
            job = _job
        if job is None:
            time.sleep(0.01)
            continue
        seed, sender, target = job
        digest = keccak256(seed + sender + nonce.to_bytes(32, "big"))
        value = int.from_bytes(digest, "big")
        if value < target:
            print(f"FOUND {nonce} {value:064x}", flush=True)
        nonce += 1
        count += 1
        now = time.monotonic()
        if now - last_rate >= 1.0:
            print(f"RATE {count / max(now - started, 1e-9):.0f}", flush=True)
            last_rate = now

threading.Thread(target=mine_loop, daemon=True).start()
for raw in sys.stdin:
    parts = raw.strip().split()
    if not parts:
        continue
    try:
        if parts[0] == "JOB" and len(parts) == 4:
            seed = bytes.fromhex(parts[1])
            sender = bytes.fromhex(parts[2])
            target = int(parts[3], 16)
            if len(seed) != 32 or len(sender) != 20:
                raise ValueError("invalid lengths")
            with _lock:
                _job = (seed, sender, target)
            print("INFO job accepted (cpu)", flush=True)
        elif parts[0] == "TX" and len(parts) >= 2:
            print("INFO tx params ready", flush=True)
            print("INFO txmode python", flush=True)
        elif parts[0] == "STOP":
            with _lock:
                _job = None
        else:
            print("ERR bad job/input", flush=True)
    except (ValueError, OverflowError):
        print("ERR bad job", flush=True)
_running = False
