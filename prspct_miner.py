"""
PRSPCT native GPU miner — orchestrator.
Runs ./prspct_cuda (CUDA keccak-256), watches contract state (seed/target/price),
feeds current job to the miner, and lets the native binary sign+broadcast claim(nonce).

ENV:
  MINER_PRIVATE_KEY  0x... burner wallet private key (required)
  RPC_URLS           comma-separated RPC endpoints (default: 3 public RH mainnet nodes)
  CUDA_BIN           path to compiled miner (default: ./prspct_cuda)
  REFRESH_SEC        state polling period (default: 0.5)
"""

import os
import random
import subprocess
import sys
import threading
import time
from queue import Queue, Empty

import requests
from eth_account import Account
from web3 import Web3

PRIVATE_KEY = os.environ.get("MINER_PRIVATE_KEY", "").strip()

DEFAULT_RPCS = ",".join([
    "https://rpc.mainnet.chain.robinhood.com",
    "https://robinhood-rpc.publicnode.com",
    "https://rpc.ordofi.network",
])
RPC_URLS = [u.strip() for u in os.environ.get("RPC_URLS", DEFAULT_RPCS).split(",") if u.strip()]
random.shuffle(RPC_URLS)

CUDA_BIN = os.environ.get("CUDA_BIN", "./prspct_cuda")
REFRESH_SEC = float(os.environ.get("REFRESH_SEC", "0.5"))

CHAIN_ID = 4663
CONTRACT = "0xd078008c3D887A52CE722A3cA0539cA1F4971dD1"

# Selectors (verified against PRSPCT_ABI)
SEL_SEED   = "0x04f10a2c"   # keccak("seed()")[:4]
SEL_TARGET = "0xc7f758a8"   # keccak("targetOf(uint256,uint256)")[:4]  — targetOf(0, 0) = pure sweat target
SEL_DEPTH  = "0x0568a5b1"   # keccak("depth()")[:4]
SEL_PRICE  = "0x6817c76c"   # keccak("priceOf(uint256)")[:4]  — priceOf(1) for sanity
SEL_STATE  = "0xc19d93fb"   # keccak("state()")[:4]

ABI = [
    {"type": "function", "name": "claim",
     "inputs": [{"name": "nonce", "type": "uint256"}],
     "outputs": [{"name": "tokenId", "type": "uint256"}],
     "stateMutability": "payable"},
]

if not (PRIVATE_KEY.startswith("0x") and len(PRIVATE_KEY) == 66):
    print("MINER_PRIVATE_KEY not set or invalid (need 0x + 64 hex)")
    sys.exit(1)

acct = Account.from_key(PRIVATE_KEY)
ADDR = acct.address


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------- RPC with rotation + backoff ----------------
class Rpc:
    def __init__(self, urls):
        self.urls = urls
        self.i = random.randrange(len(urls))
        self.backoff = 0.0
        self.sess = requests.Session()

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


def w3_for(url):
    return Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))


def bits_of(target: int) -> int:
    return 256 - target.bit_length()


def local_hash(seed: bytes, sender_hex: str, nonce: int) -> int:
    """Match the on-chain keccak256(abi.encodePacked(seed, sender, nonce)) hash."""
    data = seed + bytes.fromhex(sender_hex[2:]) + nonce.to_bytes(32, "big")
    return int.from_bytes(Web3.keccak(data), "big")


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
GAS_LIMIT = 500_000


def refresh_tx_nonce():
    global TX_NONCE
    res = rpc.call_with_retry([("eth_getTransactionCount", [ADDR, "pending"])])
    TX_NONCE = int(res[0], 16)
    return TX_NONCE


def _broadcast(raw_hex):
    """Fire raw tx at all RPCs in parallel — whoever's first wins."""
    import concurrent.futures as _cf
    errs = []

    def send(u):
        r = requests.post(u, json={"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction",
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
            return ("0x" + Web3.keccak(hexstr=raw_hex).hex().replace("0x", ""), "already-known")
    raise RuntimeError("; ".join(errs)[:150])


def submit(nonce: int, st: dict):
    """Python fallback: send claim(nonce) with value=0 (pure sweat)."""
    global TX_NONCE
    if TX_NONCE is None:
        refresh_tx_nonce()

    w3 = w3_for(rpc.url)
    c = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT), abi=ABI)
    data = c.encode_abi("claim", args=[nonce]) if hasattr(c, "encode_abi") else \
           c.encodeABI(fn_name="claim", args=[nonce])

    for attempt in range(3):
        tx = {
            "to": Web3.to_checksum_address(CONTRACT), "from": ADDR,
            "value": 0,  # pure sweat
            "data": data, "chainId": CHAIN_ID, "nonce": TX_NONCE, "gas": GAS_LIMIT,
            "maxFeePerGas": max(int(st.get("gas_price", 0) * 2), Web3.to_wei(1, "gwei")),
            "maxPriorityFeePerGas": 0,
            "type": 2,
        }
        signed = acct.sign_transaction(tx)
        raw_hex = "0x" + signed.raw_transaction.hex().replace("0x", "")
        try:
            h, via = _broadcast(raw_hex)
            TX_NONCE += 1
            log(f"[TX] sent {h} nonce={tx['nonce']} via {via.split('//')[-1][:24]}")
            rc = w3.eth.wait_for_transaction_receipt(h, timeout=180)
            log(f"[TX] status={rc['status']} block={rc['blockNumber']} gasUsed={rc['gasUsed']}")
            return rc["status"] == 1
        except Exception as e:
            msg = str(e).lower()
            if "nonce" in msg or "already known" in msg or "replacement" in msg:
                log(f"[TX] nonce issue ({str(e)[:60]}) — re-reading and retrying")
                refresh_tx_nonce()
                continue
            raise
    raise RuntimeError("failed to send: nonce conflict 3x in a row")


# ---------------- CUDA process ----------------
class Cuda:
    def __init__(self):
        self.proc = None
        self.q: Queue = Queue()
        self.start()

    def start(self):
        env = dict(os.environ, MINER_PRIVATE_KEY=PRIVATE_KEY, RPC_URLS=",".join(RPC_URLS))
        self.proc = subprocess.Popen([CUDA_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()
        log(f"[cuda] started pid={self.proc.pid}")

    def _reader(self, proc):
        for line in proc.stdout:
            self.q.put(line.rstrip("\n"))
        self.q.put(None)

    def send(self, line):
        try:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
        except Exception as e:
            log(f"[cuda] write failed: {e}")

    def restart(self):
        try:
            self.proc.kill()
        except Exception:
            pass
        time.sleep(2)
        self.start()


def main():
    log(f"[*] miner {ADDR} rpc={RPC_URLS}")

    for n in range(20):
        try:
            bal = get_balance()
            log(f"[*] balance={bal/1e18:.5f} ETH")
            if bal < 0.001e18:
                log("[!] wallet has less than 0.001 ETH — claims will fail on gas, top up")
            break
        except Exception as e:
            log(f"[WARN] balance read failed ({str(e)[:60]}), retry {n+1}/20")
            time.sleep(5)

    if not os.path.exists(CUDA_BIN):
        log(f"[!] no binary at {CUDA_BIN}")
        sys.exit(1)

    for n in range(20):
        try:
            refresh_tx_nonce()
            break
        except Exception as e:
            log(f"[WARN] nonce read failed ({str(e)[:60]}), retrying")
            time.sleep(5)

    cuda = Cuda()
    state = None
    last_refresh = 0.0
    counters = {"mined": 0, "fails": 0}
    clock = threading.Lock()

    def max_fee(st):
        return max(int(st.get("gas_price", 0) * 2), Web3.to_wei(1, "gwei"))

    def send_tx_params(st):
        cuda.send(f"TX {st['tx_nonce']} {max_fee(st)}")

    def send_job(st):
        send_tx_params(st)  # tx params first — so FOUND never fires without them
        seed_hex = st['seed'].hex()
        cuda.send(f"JOB {seed_hex} {ADDR[2:]} {st['target']:064x}")

    native_tx = {"on": False}

    def receipt_worker(txhash):
        ok = False
        try:
            w3 = w3_for(rpc.url)
            rc = w3.eth.wait_for_transaction_receipt(txhash, timeout=180)
            ok = rc["status"] == 1
            log(f"[TX] status={rc['status']} block={rc['blockNumber']} gasUsed={rc['gasUsed']} {txhash[:18]}…")
        except Exception as e:
            log(f"[TX] receipt wait failed {txhash[:18]}…: {str(e)[:80]}")
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
            log("[!] CUDA process died — restarting")
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
                log(f"[!] GPU/CPU hash mismatch — GPU lying, skipping")
                continue
            if lh >= st["target"]:
                log("[!] hash not below current target — skipping")
                continue

            if native_tx["on"]:
                log(f"[FOUND] nonce={nonce} ({bits_of(lh)} zero bits) — tx already sent from kernel (native)")
                continue
            log(f"[FOUND] nonce={nonce} ({bits_of(lh)} zero bits) — sending (GPU keeps mining)")
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
            log("[cuda]", line)


if __name__ == "__main__":
    main()
