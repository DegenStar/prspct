"""Debug helper: verify each `tx` vector from tests/crypto_selftest against its
public key (plain ECDSA verify) and recover the signer address, printing all
four candidate recovery ids. Useful when a signature looks wrong and you need to
tell "bad signature" apart from "bad recovery id".

    tests/crypto_selftest > tests/vectors.txt
    python3 tests/debug_sig.py < tests/vectors.txt
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_crypto import P, N, GX, GY, ec_mul, ec_add, inv, keccak256, rlp_encode, rlp_decode, as_int


def verify(pub, z: int, r: int, s: int) -> bool:
    w = inv(s, N)
    u1 = z * w % N
    u2 = r * w % N
    pt = ec_add(ec_mul(u1), ec_mul(u2, pub))
    return pt is not None and pt[0] % N == r


def recover(z: int, r: int, s: int, recid: int):
    x = r + (N if recid >= 2 else 0)
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2:
        return None, "x not on curve"
    if (y & 1) != (recid & 1):
        y = P - y
    point_r = (x, y)
    rinv = inv(r, N)
    q = ec_mul(s * rinv % N, point_r)
    q = ec_add(q, ec_mul((-z * rinv) % N))
    return q, None


def addr_of(point) -> str:
    return keccak256(point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))[12:].hex()


def main():
    bad = 0
    for line in (l for l in sys.stdin if l.startswith("tx ")):
        # tx <priv> <addr> <nonce> <maxFee> <tip> <raw> <txhash> <txNonce> <unsigned> <signingHash>
        parts = line.split()
        key, addr, nonce, max_fee, tip, raw, txhash, txn, unsigned_hex, sign_hash = parts[1:]
        payload, _ = rlp_decode(bytes.fromhex(raw[2:]))
        chain_id, txn_nonce, tip_enc, fee_enc, gas, to, value, data = payload[:8]
        access_list, y_parity, r_b, s_b = payload[8], payload[9], payload[10], payload[11]
        unsigned = rlp_encode([chain_id, txn_nonce, tip_enc, fee_enc, gas, to, value, data, access_list])
        assert unsigned.hex() == unsigned_hex, "rlp re-encode mismatch"
        z = int.from_bytes(keccak256(b"\x02" + unsigned), "big") % N
        assert keccak256(b"\x02" + unsigned).hex() == sign_hash, "signing hash mismatch"
        r, s = as_int(r_b), as_int(s_b)
        pub = ec_mul(int(key, 16))
        ok = verify(pub, z, r, s)
        rec = as_int(y_parity)
        q, err = recover(z, r, s, rec)
        got = addr_of(q) if q else err
        status = "ok" if (ok and got == addr) else "BAD"
        if status == "BAD":
            bad += 1
        print(f"{status} nonce={nonce} v={rec} low-S={s <= N // 2} verify={ok} recovered={got} expect={addr}")
        if status == "BAD":
            for alt in range(4):
                q2, err2 = recover(z, r, s, alt)
                print(f"      recid={alt} -> {addr_of(q2) if q2 else err2}")
    print(f"\n{bad} bad tx vectors")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
