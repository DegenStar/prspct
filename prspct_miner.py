"""
PRSPCT native miner 鈥?orchestrator.
Runs the keccak-256 miner binary (CUDA on Linux/NVIDIA, Metal+CPU on macOS),
watches contract state (seed/target/price), feeds it the current job, and lets
the native binary sign+broadcast claim(nonce).

ENV:
  MINER_PRIVATE_KEY  0x... burner wallet private key (required)
  RPC_URLS           comma-separated RPC endpoints (default: 3 public RH mainnet nodes)
  MINER_BIN          path to compiled miner (default: ./prspct_local, then ./prspct_cuda)
  CUDA_BIN           legacy alias for MINER_BIN (still honoured)
  REFRESH_SEC        state polling period (default: 0.5)
  MIN_TIP_WEI        maxPriorityFeePerGas in wei (default: 0 = pure sweat)

All of the above may also live in a .env file next to this script; variables
already exported in the shell take precedence over the file.

Only the standard library is required: web3/requests are used when installed but
are optional. Without eth-account the Python tx fallback is unavailable 鈥?that is
fine, the miner binary signs and broadcasts natively.
"""

import os
import random
import subprocess
import sys
import threading
import time
import json
import urllib.error
import urllib.request
from queue import Queue, Empty

from prspct_keccak import keccak256
from prspct_eth import privkey_to_address, to_checksum_address

try:                      # optional: connection pooling + keep-alive
    import requests
except ImportError:
    requests = None

try:                      # optional: only the Python submit fallback needs it
    from eth_account import Account
except ImportError:
    Account = None

# ---------------- .env auto-load ----------------
# Shell environment wins over the file (python-dotenv defaults to override=False),
# so `MINER_PRIVATE_KEY=0x... python3 prspct_miner.py` still overrides .env.
_ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
try:
    from dotenv import load_dotenv
except ImportError:
    def _load_env_file(path):
        """Tiny stdlib .env reader so the documented workflow works without deps."""
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].lstrip()
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                    val = val[1:-1]
                os.environ.setdefault(key, val)   # shell env still wins
    _load_env_file(_ENV_FILE)
else:
    load_dotenv(_ENV_FILE)

PRIVATE_KEY = os.environ.get("MINER_PRIVATE_KEY", "").strip()

DEFAULT_RPCS = ",".join([
    "https://rpc.mainnet.chain.robinhood.com",
    "https://robinhood-rpc.publicnode.com",
    "https://rpc.ordofi.network",
])
RPC_URLS = [u.strip() for u in os.environ.get("RPC_URLS", DEFAULT_RPCS).split(",") if u.strip()]
if not RPC_URLS:  # e.g. a blank `RPC_URLS=` line in .env
    RPC_URLS = [u.strip() for u in DEFAULT_RPCS.split(",") if u.strip()]
random.shuffle(RPC_URLS)

# Miner binary: MINER_BIN wins, CUDA_BIN is the legacy name, otherwise pick the
# first build that exists next to this script (local build first).
_here = os.path.dirname(os.path.abspath(__file__))
MINER_BIN = os.environ.get("MINER_BIN") or os.environ.get("CUDA_BIN")
if not MINER_BIN:
    # Windows toolchains emit .exe files; keep extensionless Unix names too.
    candidates = ("prspct_local", "prspct_cuda", os.path.join("prspct", "prspct_cpu.py"))
    for cand in candidates:
        for name in (cand, cand + ".exe"):
            p = os.path.join(_here, name)
            if os.path.exists(p):
                MINER_BIN = p
                break
        if MINER_BIN:
            break
    else:
        # Keep a deterministic default even before the first build exists.
        MINER_BIN = os.path.join(_here, "prspct_local" + (".exe" if os.name == "nt" else ""))
CUDA_BIN = MINER_BIN          # kept for the rest of the file
REFRESH_SEC = float(os.environ.get("REFRESH_SEC", "0.5"))

# maxPriorityFeePerGas in wei. Default 0 = pure sweat. Raise it only if your RPC
# rejects 0-tip txs ("transaction underpriced" / "tip too low").
_tip = os.environ.get("MIN_TIP_WEI", "0").strip()
MIN_TIP_WEI = int(_tip) if _tip.isdigit() else 0
if not _tip.isdigit():
    print(f"MIN_TIP_WEI={_tip!r} is not a decimal number 鈥?using 0 (pure sweat)")

CHAIN_ID = 4663
CONTRACT = "0xd078008c3D887A52CE722A3cA0539cA1F4971dD1"
GWEI = 10 ** 9

# Selectors (verified against PRSPCT_ABI)
SEL_SEED   = "0x04f10a2c"   # keccak("seed()")[:4]
SEL_TARGET = "0xc7f758a8"   # keccak("targetOf(uint256,uint256)")[:4]  鈥?targetOf(0, 0) = pure sweat target
SEL_DEPTH  = "0x0568a5b1"   # keccak("depth()")[:4]
SEL_PRICE  = "0x6817c76c"   # keccak("priceOf(uint256)")[:4]  鈥?priceOf(1) for sanity
SEL_STATE  = "0xc19d93fb"   # keccak("state()")[:4]

if not (PRIVATE_KEY.startswith("0x") and len(PRIVATE_KEY) == 66):
    print("MINER_PRIVATE_KEY not set or invalid (need 0x + 64 hex)")
    sys.exit(1)

if Account is not None:
    acct = Account.from_key(PRIVATE_KEY)
    ADDR = acct.address
else:
    # No eth-account installed: derive the address ourselves. Native tx-mode
    # (the default) signs inside the miner binary, so this is all we need.
    acct = None
    ADDR = privkey_to_address(PRIVATE_KEY)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------- RPC with rotation + backoff ----------------
class _Resp:
    """Minimal stand-in for a requests.Response (urllib fallback)."""
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return json.loads(self._body)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}: {self._body[:120]}")


class _UrllibSession:
    """Same tiny surface as requests.Session, backed by urllib (stdlib only)."""
    def post(self, url, timeout=15, **kw):
        body = json.dumps(kw.get("json")).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                             "User-Agent": "prspct-miner/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return _Resp(r.status, r.read().decode())
        except urllib.error.HTTPError as e:
            return _Resp(e.code, e.read().decode() or str(e))


def _new_session():
    return requests.Session() if requests is not None else _UrllibSession()


class Rpc:
    def __init__(self, urls):
        self.urls = urls
        self.i = random.randrange(len(urls))
        self.backoff = 0.0
        self.sess = _new_session()

    @property
    def url(self):
        return self.urls[self.i]

    def rotate(self):
        self.i = (self.i + 1) % len(self.urls)

    def batch(self, calls, timeout=15):
        payload = [{"jsonrpc": "2.0", "id": k + 1, "method": m, "params": p} for k, (m, p) in enumerate(calls)]
        r = self.sess.post(self.url, json=payload, timeout=timeout)
        if r.status_code == 429:
            raise RuntimeError("429 Too Many Requests")
        r.raise_for_status()
        j = r.json()
        if isinstance(j, dict):
            j = [j]
        by_id = {x.get("id"): x for x in j}
        out = []
        for k in range(len(calls)):
            x = by_id.get(k + 1)
            if not x or "error" in x:
                raise RuntimeError(f"rpc error: {x.get('error') if x else 'missing'}")
            out.append(x["result"])
        return out

    def call_with_retry(self, calls, attempts=10):
        last = None
        for n in range(attempts):
            try:
                res = self.batch(calls)
                self.backoff = max(0.0, self.backoff / 2)
                return res
            except Exception as e:
                last = e
                if "429" in str(e):
                    self.backoff = min(20.0, (self.backoff or 1.0) * 2)
                else:
                    self.backoff = min(5.0, (self.backoff or 0.5) * 1.5)
                wait = self.backoff * (0.5 + random.random())
                log(f"[RPC] {self.url.split('//')[1][:32]} -> {str(e)[:50]}; pause {wait:.1f}s, switching")
                self.rotate()
                time.sleep(wait)
        raise RuntimeError(f"RPC unavailable: {last}")


rpc = Rpc(RPC_URLS)


def wait_receipt(tx_hash, timeout=180):
    """Poll eth_getTransactionReceipt until mined (or timeout)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = rpc.call_with_retry([("eth_getTransactionReceipt", [tx_hash])], attempts=3)
        if res[0]:
            return res[0]
        time.sleep(1.0)
    raise TimeoutError(f"no receipt for {tx_hash} within {timeout}s")


def bits_of(target: int) -> int:
    return 256 - target.bit_length()


def local_hash(seed: bytes, sender_hex: str, nonce: int) -> int:
    """Match the on-chain keccak256(abi.encodePacked(seed, sender, nonce)) hash."""
    data = seed + bytes.fromhex(sender_hex[2:]) + nonce.to_bytes(32, "big")
    return int.from_bytes(keccak256(data), "big")


def read_state():
    """Single batch: state() [gives seed, depth, price, target], gasPrice, nonce."""
    to = CONTRACT
    res = rpc.call_with_retry([
        ("eth_call", [{"to": to, "data": SEL_STATE}, "latest"]),
        ("eth_gasPrice", []),
        ("eth_getTransactionCount", [ADDR, "pending"]),
    ])
    # state() returns tuple: (depth, seed, openAt, price, target, coinWeight, sweatWeight,
    #                        coinIn, tillPaid, day, pot, best, who, companyOwed)
    # Each field is 32 bytes in the ABI-encoded tuple.
    s = res[0][2:]  # strip 0x

    # Fail loudly on ABI drift: a short tuple would silently shift every index
    # below and we would mine against a bogus target forever.
    if len(s) % 64 or len(s) // 64 < 14:
        raise RuntimeError(f"state() ABI drift: got {len(s)} hex chars, expected >= 14 words")

    def word(n):
        return s[n * 64:(n + 1) * 64]

    depth       = int(word(0), 16)
    seed        = bytes.fromhex(word(1))
    open_at     = int(word(2), 16)
    price       = int(word(3), 16)
    target      = int(word(4), 16)
    coin_weight = int(word(5), 16)
    sweat_weight = int(word(6), 16)
    coin_in     = int(word(7), 16)
    till_paid   = int(word(8), 16)
    day         = int(word(9), 16)
    pot         = int(word(10), 16)

    gas_price = int(res[1], 16)
    tx_nonce  = int(res[2], 16)

    return {
        "depth": depth, "seed": seed, "open_at": open_at, "price": price, "target": target,
        "coin_weight": coin_weight, "sweat_weight": sweat_weight, "coin_in": coin_in,
        "till_paid": till_paid, "day": day, "pot": pot,
        "gas_price": gas_price, "tx_nonce": tx_nonce,
    }


def get_balance():
    res = rpc.call_with_retry([("eth_getBalance", [ADDR, "latest"])])
    return int(res[0], 16)


TX_NONCE = None
TX_NONCE_LOCK = threading.Lock()
GAS_LIMIT = 500_000


def _read_pending_nonce():
    res = rpc.call_with_retry([("eth_getTransactionCount", [ADDR, "pending"])])
    return int(res[0], 16)


def refresh_tx_nonce():
    global TX_NONCE
    with TX_NONCE_LOCK:
        TX_NONCE = _read_pending_nonce()
        return TX_NONCE


def reserve_tx_nonce():
    """Atomically claim the next nonce 鈥?concurrent FOUND workers must not collide."""
    global TX_NONCE
    with TX_NONCE_LOCK:
        if TX_NONCE is None:
            TX_NONCE = _read_pending_nonce()
        n = TX_NONCE
        TX_NONCE += 1
        return n


def _broadcast(raw_hex):
    """Fire raw tx at all RPCs in parallel 鈥?whoever's first wins."""
    import concurrent.futures as _cf
    errs = []

    def send(u):
        r = _new_session().post(u, json={"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction",
                                         "params": [raw_hex]}, timeout=8)
        j = r.json()
        if j.get("result"):
            return (j["result"], u)
        raise RuntimeError(str(j.get("error"))[:80])

    with _cf.ThreadPoolExecutor(max_workers=len(RPC_URLS)) as ex:
        futs = {ex.submit(send, u): u for u in RPC_URLS}
        for f in _cf.as_completed(futs):
            try:
                return f.result()
            except Exception as e:
                errs.append(str(e))
    for e in errs:
        if "already known" in e.lower() or "known transaction" in e.lower():
            return ("0x" + keccak256(bytes.fromhex(raw_hex[2:])).hex(), "already-known")
    raise RuntimeError("; ".join(errs)[:150])


# claim(uint256) calldata: selector + 32-byte nonce (identical to the C++ side)
SEL_CLAIM = keccak256(b"claim(uint256)")[:4]
CONTRACT_ADDR = to_checksum_address(CONTRACT)


def submit(nonce: int, st: dict):
    """Python fallback: send claim(nonce) with value=0 (pure sweat)."""
    if acct is None:
        raise RuntimeError("Python submit needs eth-account 鈥?run `pip install -r requirements.txt` "
                           "or rely on native tx-mode (the miner binary signs the claim itself)")
    data = SEL_CLAIM + nonce.to_bytes(32, "big")

    for attempt in range(3):
        tx_nonce = reserve_tx_nonce()
        tx = {
            "to": CONTRACT_ADDR, "from": ADDR,
            "value": 0,  # pure sweat
            "data": data, "chainId": CHAIN_ID, "nonce": tx_nonce, "gas": GAS_LIMIT,
            "maxFeePerGas": max(int(st.get("gas_price", 0) * 2), GWEI),
            "maxPriorityFeePerGas": MIN_TIP_WEI,
            "type": 2,
        }
        signed = acct.sign_transaction(tx)
        raw_hex = "0x" + signed.raw_transaction.hex().replace("0x", "")
        try:
            h, via = _broadcast(raw_hex)
            log(f"[TX] sent {h} nonce={tx_nonce} via {via.split('//')[-1][:24]}")
            rc = wait_receipt(h, timeout=180)
            log(f"[TX] status={rc['status']} block={rc['blockNumber']} gasUsed={rc['gasUsed']}")
            return int(rc["status"], 16) == 1 if isinstance(rc["status"], str) else rc["status"] == 1
        except Exception as e:
            msg = str(e).lower()
            # Any failure may mean our local nonce drifted from the chain
            # (tx rejected, node timed out, or it landed despite the error).
            log(f"[TX] nonce={tx_nonce} failed ({str(e)[:80]}) 鈥?resyncing nonce")
            try:
                refresh_tx_nonce()
            except Exception as re_:
                log(f"[WARN] nonce resync failed: {str(re_)[:60]}")
            if "nonce" in msg or "already known" in msg or "replacement" in msg:
                continue
            raise
    raise RuntimeError("failed to send: nonce conflict 3x in a row")


# ---------------- miner process (CUDA or local Metal/CPU build) ----------------
class Miner:
    def __init__(self):
        self.proc = None
        self.q: Queue = Queue()
        self.start()

    def start(self):
        env = dict(os.environ, MINER_PRIVATE_KEY=PRIVATE_KEY, RPC_URLS=",".join(RPC_URLS))
        command = [sys.executable, CUDA_BIN] if CUDA_BIN.lower().endswith('.py') else [CUDA_BIN]
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()
        log(f"[miner] started {os.path.basename(CUDA_BIN)} pid={self.proc.pid}")

    def _reader(self, proc):
        for line in proc.stdout:
            self.q.put(line.rstrip("\n"))
        self.q.put(None)

    def send(self, line):
        try:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
        except Exception as e:
            log(f"[miner] write failed: {e}")

    def restart(self):
        try:
            self.proc.kill()
        except Exception:
            pass
        time.sleep(2)
        self.start()


def main():
    log(f"[*] miner {ADDR}")
    log(f"[*] binary {CUDA_BIN} rpc={RPC_URLS}")

    for n in range(20):
        try:
            bal = get_balance()
            log(f"[*] balance={bal/1e18:.5f} ETH")
            if bal < 0.001e18:
                log("[!] wallet has less than 0.001 ETH 鈥?claims will fail on gas, top up")
            break
        except Exception as e:
            log(f"[WARN] balance read failed ({str(e)[:60]}), retry {n+1}/20")
            time.sleep(5)

    if not os.path.exists(CUDA_BIN):
        log(f"[!] no miner binary at {CUDA_BIN} 鈥?build it first (`make` on macOS, "
            f"nvcc -o prspct_cuda prspct_cuda.cu -lsecp256k1 -lcurl -lpthread` on NVIDIA)")
        sys.exit(1)

    for n in range(20):
        try:
            refresh_tx_nonce()
            break
        except Exception as e:
            log(f"[WARN] nonce read failed ({str(e)[:60]}), retrying")
            time.sleep(5)

    cuda = Miner()
    state = None
    last_refresh = 0.0
    counters = {"mined": 0, "fails": 0}
    clock = threading.Lock()

    def max_fee(st):
        return max(int(st.get("gas_price", 0) * 2), GWEI)

    def send_tx_params(st):
        cuda.send(f"TX {st['tx_nonce']} {max_fee(st)}")

    def send_job(st):
        send_tx_params(st)  # tx params first 鈥?so FOUND never fires without them
        seed_hex = st['seed'].hex()
        cuda.send(f"JOB {seed_hex} {ADDR[2:]} {st['target']:064x}")

    native_tx = {"on": False}

    def receipt_worker(txhash):
        ok = False
        try:
            rc = wait_receipt(txhash, timeout=180)
            ok = int(rc["status"], 16) == 1 if isinstance(rc["status"], str) else rc["status"] == 1
            log(f"[TX] status={rc[\x27status\x27]} block={rc[\x27blockNumber\x27]} gasUsed={rc[\x27gasUsed\x27]} {txhash[:18]}")
        except Exception as e:
            log(f"[TX] receipt wait failed {txhash[:18]}鈥? {str(e)[:80]}")
        with clock:
            if ok:
                counters["mined"] += 1
                log(f"[OK] SHARE CLAIMED! total: {counters['mined']}")
            else:
                counters["fails"] += 1

    def submit_worker(nonce, st):
        try:
            ok = submit(nonce, st)
        except Exception as e:
            ok = False
            log(f"[FAIL] submit: {str(e)[:200]}")
        with clock:
            if ok:
                counters["mined"] += 1
                log(f"[OK] SHARE CLAIMED! total: {counters['mined']}")
            else:
                counters["fails"] += 1

    while True:
        now = time.time()
        if now - last_refresh >= REFRESH_SEC:
            last_refresh = now
            try:
                st = read_state()
                # Re-issue job only when seed or target changes; otherwise just refresh tx params.
                seed_changed   = state is None or st["seed"] != state["seed"]
                target_changed = state is not None and st["target"] != state["target"]
                if seed_changed or target_changed:
                    b = bits_of(st['target'])
                    log(f"[STATE] {'seed' if seed_changed else 'target'} changed | depth={st['depth']}/8888 "
                        f"| target={b} bits | price={st['price']/1e18:.5f} ETH | pot={st['pot']/1e18:.4f} ETH")
                    state = st
                    send_job(st)
                else:
                    state["price"] = st["price"]
                    state["gas_price"] = st["gas_price"]
                    state["tx_nonce"] = st["tx_nonce"]
                    state["depth"] = st["depth"]
                    state["pot"] = st["pot"]
                    send_tx_params(state)
            except Exception as e:
                log(f"[WARN] state read failed: {str(e)[:100]}")

        try:
            line = cuda.q.get(timeout=0.3)
        except Empty:
            continue

        if line is None:
            log("[!] miner process died 鈥?restarting")
            cuda.restart()
            if state:
                send_job(state)
            continue

        if line.startswith("RATE"):
            rate = float(line.split()[1])
            b = bits_of(state["target"]) if state else 0
            eta = (2 ** b) / rate / 3600 if rate and b else 0
            log(f"[RATE] {rate/1e9:.2f} GH/s | target {b or '?'} bits | avg wait ~{eta:.2f}h | "
                f"mined={counters['mined']} fails={counters['fails']} depth={state['depth'] if state else '?'}/8888")
        elif line.startswith("FOUND"):
            _, nonce_s, hash_hex = line.split()
            nonce = int(nonce_s)
            st = state
            if not st:
                continue
            lh = local_hash(st["seed"], ADDR, nonce)
            if f"{lh:064x}" != hash_hex:
                log(f"[!] GPU/CPU hash mismatch 鈥?GPU lying, skipping")
                continue
            if lh >= st["target"]:
                log("[!] hash not below current target 鈥?skipping")
                continue

            if native_tx["on"]:
                log(f"[FOUND] nonce={nonce} ({bits_of(lh)} zero bits) 鈥?tx already sent from kernel (native)")
                continue
            log(f"[FOUND] nonce={nonce} ({bits_of(lh)} zero bits) 鈥?sending (GPU keeps mining)")
            threading.Thread(target=submit_worker, args=(nonce, dict(st)), daemon=True).start()
        elif line.startswith("SENT"):
            parts = line.split()
            log(f"[TX] sent {parts[1]} txNonce={parts[3]} (native)")
            threading.Thread(target=receipt_worker, args=(parts[1],), daemon=True).start()
        elif line.startswith("TXRES"):
            log("[TX]", line[6:])
        elif line.startswith("INFO") or line.startswith("ERR") or "error" in line.lower():
            if "txmode native" in line:
                native_tx["on"] = True
            elif "txmode python" in line:
                native_tx["on"] = False
            log("[miner]", line)


if __name__ == "__main__":
    main()


