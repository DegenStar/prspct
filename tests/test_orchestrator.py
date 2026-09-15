"""Offline tests for prspct_miner.py — no chain, no web3, no network.

    python3 tests/test_orchestrator.py
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PRIV = "0x" + "00" * 31 + "01"
os.environ["MINER_PRIVATE_KEY"] = PRIV
os.environ["MINER_BIN"] = os.path.join(ROOT, "prspct_local")

import prspct_miner as m            # noqa: E402
from prspct_keccak import claim_hash, keccak256  # noqa: E402

FAILED = 0


def check(cond, label, detail=""):
    global FAILED
    if cond:
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label} {detail}")


def word(v):
    return f"{v:064x}"


STATE_WORDS = [
    12,                                                                  # depth
    int("aa" * 32, 16),                                                  # seed
    1700000000,                                                          # openAt
    int(0.05e18),                                                        # price
    (1 << 208) - 1,                                                      # target (48 leading zeros)
    5, 7, 1, 0, 3, int(2.5e18), 0, 0, 0,                                 # weights/pot/etc
]


def fake_batch(calls, timeout=15):
    out = []
    for method, params in calls:
        if method == "eth_call":
            out.append("0x" + "".join(word(w) for w in STATE_WORDS))
        elif method == "eth_gasPrice":
            out.append(hex(2 * 10 ** 9))
        elif method == "eth_getTransactionCount":
            out.append(hex(5))
        elif method == "eth_getBalance":
            out.append(hex(10 ** 18))
        elif method == "eth_getTransactionReceipt":
            out.append(RECEIPT_QUEUE.pop(0) if RECEIPT_QUEUE else None)
        else:
            raise AssertionError(f"unexpected rpc {method}")
    return out


RECEIPT_QUEUE = []


class FakeAcct:
    def __init__(self):
        self.tx = None

    def sign_transaction(self, tx):
        self.tx = tx

        class Signed:
            raw_transaction = bytes.fromhex("02" + "ab" * 40)
        return Signed()


def test_address():
    check(m.ADDR == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "privkey 1 -> known address", m.ADDR)
    check(m.ADDR == m.privkey_to_address(PRIV), "address derivation consistent")


def test_local_hash():
    seed = bytes(range(32))
    sender = "0x" + "11" * 20
    check(m.local_hash(seed, sender, 12345) == claim_hash(seed, sender, 12345), "local_hash matches keccak")
    check(m.local_hash(seed, sender, 12345) == int.from_bytes(
        keccak256(seed + bytes([0x11] * 20) + (12345).to_bytes(32, "big")), "big"), "local_hash preimage")


def test_read_state():
    m.rpc.batch = fake_batch
    st = m.read_state()
    check(st["depth"] == 12, "state depth", st["depth"])
    check(st["seed"] == bytes.fromhex("aa" * 32), "state seed")
    check(st["target"] == (1 << 208) - 1, "state target")
    check(m.bits_of(st["target"]) == 48, "target bits", m.bits_of(st["target"]))
    check(st["gas_price"] == 2 * 10 ** 9, "gas price", st["gas_price"])
    check(st["tx_nonce"] == 5, "tx nonce", st["tx_nonce"])
    check(abs(st["price"] - 0.05e18) < 1, "price", st["price"])


def test_wait_receipt():
    m.rpc.batch = fake_batch
    RECEIPT_QUEUE.clear()
    RECEIPT_QUEUE.extend([None, {"status": "0x1", "blockNumber": "0x20", "gasUsed": "0x5208"}])
    rc = m.wait_receipt("0xdeadbeef", timeout=10)
    check(rc["status"] == "0x1", "receipt polled until mined", rc)


def test_submit():
    m.rpc.batch = fake_batch
    fake = FakeAcct()
    m.acct = fake
    m.acct.address = m.ADDR
    m.MIN_TIP_WEI = 0
    m.TX_NONCE = 41
    captured = {}

    def fake_broadcast(raw_hex):
        captured["raw"] = raw_hex
        return ("0x" + "cd" * 32, "unit-test")

    def fake_receipt(tx_hash, timeout=180):
        captured["hash"] = tx_hash
        return {"status": "0x1", "blockNumber": "0x21", "gasUsed": "0x5208"}

    m._broadcast = fake_broadcast
    m.wait_receipt = fake_receipt
    ok = m.submit(0xCAFE, {"gas_price": 2 * 10 ** 9})
    check(ok is True, "submit returns success on status 1")
    tx = fake.tx
    check(tx["to"] == m.CONTRACT_ADDR, "tx to contract", tx["to"])
    check(tx["value"] == 0, "tx value = 0 (pure sweat)", tx["value"])
    check(tx["data"] == m.SEL_CLAIM + (0xCAFE).to_bytes(32, "big"), "tx calldata claim(nonce)")
    check(tx["type"] == 2 and tx["chainId"] == 4663, "tx is EIP-1559 on chain 4663")
    check(tx["nonce"] == 41, "tx nonce reserved from local counter", tx["nonce"])
    check(tx["maxFeePerGas"] == max(4 * 10 ** 9, 10 ** 9), "maxFeePerGas = 2x gasPrice", tx["maxFeePerGas"])
    check(tx["maxPriorityFeePerGas"] == 0, "tip = 0")
    check(captured["raw"].startswith("0x02"), "raw tx is type-2", captured["raw"][:6])


def test_submit_without_eth_account():
    m.acct = None
    try:
        m.submit(1, {"gas_price": 1})
        check(False, "submit without eth-account raises")
    except RuntimeError as e:
        check("eth-account" in str(e), "submit without eth-account raises", str(e)[:60])


def test_env_file_parser():
    if not hasattr(m, "_load_env_file"):
        print("  skip .env parser (python-dotenv installed)")
        return
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, ".env")
        with open(path, "w") as fh:
            fh.write("# comment\n\nMINER_PRIVATE_KEY=0xabc\nexport FOO='bar'\nBAZ=1\n")
        os.environ.pop("FOO", None)
        os.environ.pop("BAZ", None)
        os.environ["MINER_PRIVATE_KEY"] = "keep-me"     # shell env must win
        m._load_env_file(path)
        check(os.environ["FOO"] == "bar", "env file: export + quotes", os.environ.get("FOO"))
        check(os.environ["BAZ"] == "1", "env file: plain value")
        check(os.environ["MINER_PRIVATE_KEY"] == "keep-me", "env file does not override shell")


def test_miner_plumbing():
    """Start the real binary through the orchestrator's Miner wrapper."""
    if not os.path.exists(m.CUDA_BIN):
        print("  skip miner plumbing (binary not built)")
        return
    env_backup = os.environ.get("MINER_PRIVATE_KEY")
    os.environ["MINER_PRIVATE_KEY"] = PRIV
    m.PRIVATE_KEY = PRIV
    try:
        miner = m.Miner()
        miner.send(f"JOB {'ab' * 32} {'cd' * 20} {1:064x}")
        miner.send("TX 1 1000000000")
        got = []
        for _ in range(60):
            line = miner.q.get(timeout=5)
            if line is None:
                break
            got.append(line)
            if any("job accepted" in l for l in got) and any("tx params ready" in l for l in got):
                break
        check(any("txmode native" in l for l in got), "miner runs in native tx-mode", got[:4])
        check(any("job accepted" in l for l in got), "miner accepted the job")
        miner.proc.kill()
    finally:
        if env_backup is None:
            os.environ.pop("MINER_PRIVATE_KEY", None)
        else:
            os.environ["MINER_PRIVATE_KEY"] = env_backup


if __name__ == "__main__":
    test_address()
    test_local_hash()
    test_read_state()
    test_wait_receipt()
    test_submit()
    test_submit_without_eth_account()
    test_env_file_parser()
    test_miner_plumbing()
    print(f"\n{FAILED} failures")
    sys.exit(1 if FAILED else 0)
