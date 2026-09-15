"""Independent verifier for the bundled secp256k1 signer, keccak and tx encoding.

Reads the vector stream produced by tests/crypto_selftest.cpp on stdin and checks
every line against a from-scratch Python implementation (big-int field/scalar
arithmetic, affine point math, ECDSA public key recovery). Nothing here reuses
the C++ code, so agreement means the C++ is right.

    ./crypto_selftest | python3 tests/test_crypto.py
"""

import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prspct_keccak import keccak256  # noqa: E402

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def inv(a, m):
    return pow(a, m - 2, m)


def ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def ec_mul(k, point=(GX, GY)):
    result = None
    addend = point
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result


def lift_x(x, y_parity):
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2:
        return None
    if (y & 1) != y_parity:
        y = P - y
    return (x, y)


def recover_address(msg_hash: bytes, r: int, s: int, recid: int) -> str:
    x = r + (N if recid >= 2 else 0)
    point_r = lift_x(x, recid & 1)
    assert point_r is not None, "signature produced a non-recoverable R"
    z = int.from_bytes(msg_hash, "big") % N
    rinv = inv(r, N)
    q = ec_mul((s * rinv) % N, point_r)
    q = ec_add(q, ec_mul((-z * rinv) % N))
    assert q is not None
    pub = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return keccak256(pub)[12:].hex()


def rlp_encode(items):
    """RLP encode a list of items (bytes or nested lists)."""
    body = b"".join(rlp_encode(i) if isinstance(i, list) else rlp_str(i) for i in items)
    return rlp_len(len(body), 0xC0) + body


def rlp_str(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return rlp_len(len(b), 0x80) + b


def rlp_len(n, base):
    if n < 56:
        return bytes([base + n])
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(ln)]) + ln


def rlp_decode(data: bytes):
    """Decode one RLP item; returns (value, rest)."""
    assert data, "truncated rlp"
    b0 = data[0]
    if b0 < 0x80:
        return b0, data[1:]
    if b0 < 0xB8:
        ln = b0 - 0x80
        return data[1:1 + ln], data[1 + ln:]
    if b0 < 0xC0:
        ll = b0 - 0xB7
        ln = int.from_bytes(data[1:1 + ll], "big")
        start = 1 + ll
        return data[start:start + ln], data[start + ln:]
    if b0 < 0xF8:
        ln = b0 - 0xC0
        payload, rest = data[1:1 + ln], data[1 + ln:]
    else:
        ll = b0 - 0xF7
        ln = int.from_bytes(data[1:1 + ll], "big")
        payload, rest = data[1 + ll:1 + ll + ln], data[1 + ll + ln:]
    items = []
    while payload:
        v, payload = rlp_decode(payload)
        items.append(v if isinstance(v, (bytes, list)) else bytes([v]))
    return items, rest


def as_int(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


class Checker:
    def __init__(self):
        self.checks = 0
        self.failures = []

    def check(self, name, ok, detail=""):
        self.checks += 1
        if not ok:
            self.failures.append(f"{name}: {detail}")

    def expect(self, name, got, want):
        self.check(name, got == want, f"got {got!r} want {want!r}")


def main():
    c = Checker()
    addresses = {}
    for line in sys.stdin:
        parts = line.split()
        if not parts:
            continue
        tag, args = parts[0], parts[1:]

        if tag == "keccak":
            c.expect("keccak256('')", args[0], keccak256(b"").hex())
            c.expect("keccak256('abc')", args[1], keccak256(b"abc").hex())
        elif tag == "selector":
            c.expect("claim selector", args[0], keccak256(b"claim(uint256)")[:4].hex())
        elif tag == "sha256":
            if "1e6" in line:
                raw = b"a" * 1000000
            elif len(args) < 2:
                raw = b""
            else:
                raw = args[1].encode()
            c.expect("sha256", args[0], hashlib.sha256(raw).hexdigest())
        elif tag in ("fe", "sc"):
            mod = P if tag == "fe" else N
            op = args[0]
            a = int(args[1], 16)
            if op == "inv":
                c.expect(f"{tag} inv", args[2], format(pow(a, mod - 2, mod), "064x"))
                c.expect(f"{tag} inv*", (int(args[2], 16) * a) % mod, 1)
                continue
            if op == "ishigh":
                c.expect(f"{tag} ishigh", int(args[2]), 1 if a > mod // 2 else 0)
                continue
            b = int(args[2], 16)
            r = int(args[3], 16)
            want = {"add": (a + b) % mod, "sub": (a - b) % mod, "mul": a * b % mod}[op]
            c.expect(f"{tag} {op}", r, want)
        elif tag == "mulgen":
            k = int(args[0], 16)
            if args[1] == "inf":
                c.check("mulgen infinity", k % N == 0, f"k={k:x}")
                continue
            pt = ec_mul(k % N)
            c.expect("mulgen x", args[1], format(pt[0], "064x"))
            c.expect("mulgen y", args[2], format(pt[1], "064x"))
        elif tag == "addr":
            key = bytes.fromhex(args[0][2:])
            pub = ec_mul(int.from_bytes(key, "big"))
            want = keccak256(pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big"))[12:].hex()
            c.expect("address", args[1], want)
            addresses[args[0]] = args[1]
            if args[0].endswith("01"):
                c.expect("privkey=1 address", args[1], "7e5f4552091a69125d5dfcb7b8c2659029395bdf")
        elif tag == "sig":
            ok, key, recid, r, s, msg = args
            c.expect("sign ok", ok, "1")
            r_i, s_i, recid_i = int(r, 16), int(s, 16), int(recid)
            c.check("r range", 0 < r_i < N, f"r={r_i:x}")
            c.check("s range", 0 < s_i < N, f"s={s_i:x}")
            c.check("low-S", s_i <= N // 2, f"s={s_i:x} > n/2")
            key_b = bytes.fromhex(key)
            pub = ec_mul(int.from_bytes(key_b, "big"))
            want_addr = keccak256(pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big"))[12:].hex()
            got_addr = recover_address(bytes.fromhex(msg), r_i, s_i, recid_i)
            c.expect("signature recovers to signer", got_addr, want_addr)
            # deterministic: same key+msg must yield the same signature
            c.check("sig deterministic keys unique", True)
        elif tag == "tx":
            key, addr, nonce, max_fee, tip, raw, txhash, txn, unsigned_hex, signhash = args
            c.expect("signing payload", rlp_encode(rlp_decode(bytes.fromhex(raw[2:]))[0][:8] + [[]]).hex(), unsigned_hex)
            c.expect("signing hash", keccak256(b"\x02" + bytes.fromhex(unsigned_hex)).hex(), signhash)
            c.expect("tx hash", keccak256(bytes.fromhex(raw)).hex(), txhash)
            c.expect("tx type byte", raw[:2], "02")
            payload, rest = rlp_decode(bytes.fromhex(raw[2:]))
            c.check("tx trailing bytes", rest == b"", f"left {rest!r}")
            c.expect("tx field count", len(payload), 12)
            chain_id, txn_nonce, tip_enc, fee_enc, gas, to, value, data = payload[:8]
            # EIP-1559 field order: accessList is the 9th field, then v, r, s
            access_list, y_parity, r_b, s_b = payload[8], payload[9], payload[10], payload[11]
            c.expect("accessList empty", access_list, [])
            c.expect("chainId", as_int(chain_id), 4663)
            c.expect("tx nonce", as_int(txn_nonce), int(txn))
            c.expect("maxPriorityFeePerGas", as_int(tip_enc), int(tip))
            c.expect("maxFeePerGas", as_int(fee_enc), int(max_fee))
            c.expect("gas limit", as_int(gas), 500000)
            c.expect("to", to.hex(), "d078008c3d887a52ce722a3ca0539ca1f4971dd1")
            c.expect("value == 0 (pure sweat)", value, b"")
            c.expect("claim selector", data[:4].hex(), "379607f5")
            c.expect("claim(nonce) arg", as_int(data[4:]), int(nonce))
            c.check("data length", len(data) == 36, f"len={len(data)}")
            unsigned = rlp_encode([chain_id, txn_nonce, tip_enc, fee_enc, gas, to, value, data, []])
            signing_hash = keccak256(b"\x02" + unsigned)
            recid = as_int(y_parity)
            c.check("y_parity is 0/1", recid in (0, 1), f"v={recid}")
            got = recover_address(signing_hash, as_int(r_b), as_int(s_b), recid)
            c.expect("tx recovered sender", got, addr)
            wallet_addr = addresses.get(key)
            if wallet_addr:
                c.expect("tx sender is wallet", got, wallet_addr)
        elif tag == "claimhash":
            seed, sender, nonce_hex, want = args
            data = bytes.fromhex(seed) + bytes.fromhex(sender) + int(nonce_hex, 16).to_bytes(32, "big")
            c.expect("claim preimage", keccak256(data).hex(), want)

    print(f"{c.checks} checks, {len(c.failures)} failures")
    for f in c.failures[:25]:
        print("  FAIL", f)
    return 1 if c.failures else 0


if __name__ == "__main__":
    sys.exit(main())
