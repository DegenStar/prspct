"""Minimal pure-Python keccak-256 (Ethereum variant, not SHA3-256).

Used as the zero-dependency fallback by prspct_miner.py so the orchestrator can
verify GPU results on machines without web3/eth-hash installed. Slow on purpose
of being obvious: it only ever hashes a handful of 84-byte messages per found
share, never the mining inner loop.
"""

MASK = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# rotation offsets, indexed [x + 5*y]
_ROT = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK if n else x


def _keccak_f(a):
    b = [0] * 25
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            dx = d[x]
            for y in range(5):
                a[x + 5 * y] ^= dx
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], _ROT[x + 5 * y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        a[0] ^= _RC[rnd]
    return a


def keccak256(data: bytes) -> bytes:
    """keccak256 (legacy Keccak padding 0x01, rate 136) — what Ethereum uses."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0x00)
    padded[-1] |= 0x80

    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f(state)
    return b"".join(x.to_bytes(8, "little") for x in state[:4])


def claim_hash(seed: bytes, sender_hex: str, nonce: int) -> int:
    """keccak256(abi.encodePacked(bytes32 seed, address sender, uint256 nonce))."""
    sender = bytes.fromhex(sender_hex[2:] if sender_hex.startswith("0x") else sender_hex)
    data = seed + sender + nonce.to_bytes(32, "big")
    return int.from_bytes(keccak256(data), "big")


if __name__ == "__main__":
    # keccak256("") — the canonical Ethereum anchor value
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    print("prspct_keccak.py self-test ok")
