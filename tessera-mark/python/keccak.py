"""Pure-Python Keccak-f[1600], cSHAKE256 and KMAC256 (NIST FIPS 202, SP 800-185).

Reference-only: written for clarity and test vectors, not speed or side-channel resistance.
"""

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M = (1 << 64) - 1
RATE_256 = 136  # bytes, capacity 512 bits


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def keccak_f(a):
    """Permutes a 5x5 list of 64-bit lanes in place (a[x][y])."""
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def _sponge(data: bytes, suffix: int, out_len: int, rate: int = RATE_256) -> bytes:
    a = [[0] * 5 for _ in range(5)]
    msg = bytearray(data)
    msg.append(suffix)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            a[i % 5][i // 5] ^= lane
        keccak_f(a)
    out = bytearray()
    while len(out) < out_len:
        for i in range(rate // 8):
            out += a[i % 5][i // 5].to_bytes(8, "little")
        if len(out) < out_len:
            keccak_f(a)
    return bytes(out[:out_len])


def left_encode(x: int) -> bytes:
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, "big")


def right_encode(x: int) -> bytes:
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, "big") + bytes([n])


def encode_string(s: bytes) -> bytes:
    return left_encode(8 * len(s)) + s


def bytepad(x: bytes, w: int) -> bytes:
    z = left_encode(w) + x
    return z + b"\x00" * ((-len(z)) % w)


def shake256(data: bytes, out_len: int) -> bytes:
    return _sponge(data, 0x1F, out_len)


def cshake256(data: bytes, out_len: int, n: bytes = b"", s: bytes = b"") -> bytes:
    if not n and not s:
        return shake256(data, out_len)
    prefix = bytepad(encode_string(n) + encode_string(s), RATE_256)
    return _sponge(prefix + data, 0x04, out_len)


def kmac256(key: bytes, data: bytes, out_len: int, custom: bytes = b"") -> bytes:
    """KMAC256(K, X, L, S) per SP 800-185 section 4.3, L = 8 * out_len."""
    x = bytepad(encode_string(key), RATE_256) + data + right_encode(8 * out_len)
    return cshake256(x, out_len, b"KMAC", custom)
