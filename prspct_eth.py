"""Ethereum helpers that need nothing but the standard library.

Only what the orchestrator cannot get from the chain: EIP-55 checksummed
addresses and the address derived from a burner private key. Keccak comes from
prspct_keccak, which keeps the whole path free of compiled dependencies.
"""

from prspct_keccak import keccak256

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (GX, GY)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, point=_G):
    result, addend = None, point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def to_checksum_address(addr: str) -> str:
    """EIP-55 mixed-case checksum address."""
    a = addr.lower().replace("0x", "")
    h = keccak256(a.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))


def privkey_to_address(priv_hex: str) -> str:
    """Address for a 0x-prefixed 32-byte private key (compressed pubkey -> keccak)."""
    key = int(priv_hex[2:] if priv_hex.startswith("0x") else priv_hex, 16)
    if not (0 < key < N):
        raise ValueError("private key out of range")
    x, y = _mul(key)
    return to_checksum_address(keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:].hex())
