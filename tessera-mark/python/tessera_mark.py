"""TesseraMark DRAFT v0.1 reference prototype (see ../SPEC.md).

A TesseraMark is a short keyed code (24-64 bits) embedded in a forensic watermark. It is a
keyed permutation of a per-asset allocation index, so codes are unique per asset, look random,
reveal nothing about order or session counts, and invert back to the index without a search.
"""
from dataclasses import dataclass

from keccak import kmac256, shake256, left_encode, encode_string

VARIANT = 0x05
RECORD_LEN = 16
FEISTEL_ROUNDS = 12
MIN_KEY_LEN = 32
_CUSTOM = b"TesseraMark v1"
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"


class MarkError(ValueError):
    """Every decode failure; .code names the reason (mirrors tessera error-enum style)."""

    def __init__(self, code: str, msg: str = ""):
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


@dataclass(frozen=True)
class Profile:
    name: str
    pid: int
    code_bits: int
    check_bits: int

    @property
    def channel_bits(self) -> int:
        return self.code_bits + self.check_bits

    @property
    def max_erasures(self) -> int:
        """Erased positions the decoder may brute-force while keeping >= 12 check bits of margin."""
        return max(0, self.check_bits - 12)


PROFILES = {p.pid: p for p in (
    Profile("TM24", 0x01, 24, 12),
    Profile("TM32", 0x02, 32, 16),
    Profile("TM40", 0x03, 40, 16),
    Profile("TM48", 0x04, 48, 16),
    Profile("TM64", 0x05, 64, 16),
)}
BY_NAME = {p.name: p for p in PROFILES.values()}


def _sub(asset_key: bytes, label: bytes, n: int = 32) -> bytes:
    return kmac256(asset_key, label, n, _CUSTOM + b" subkey")


def derive_asset_key(master: bytes, tenant: bytes, asset_id: bytes, asset_hash: bytes = b"") -> bytes:
    """K_asset = KMAC256(K_master, encode(tenant)||encode(asset TesseraID)||encode(TesseraHash), 256).

    Every field is length-prefixed (SP 800-185 encode_string) so contexts cannot be confused.
    """
    if len(master) < MIN_KEY_LEN:
        raise MarkError("SHORT_KEY", "master key must be >= 32 bytes")
    ctx = encode_string(tenant) + encode_string(asset_id) + encode_string(asset_hash)
    return kmac256(master, ctx, 32, _CUSTOM + b" asset key")


def asset_tag(asset_id: bytes) -> bytes:
    """6-byte public routing tag of the asset (not secret; lets a record name its asset)."""
    return shake256(b"TesseraMark v1 asset tag" + encode_string(asset_id), 6)


class Mark:
    """Per-(asset, profile) codec. Holds subkeys derived from the asset key."""

    def __init__(self, asset_key: bytes, profile: Profile):
        if len(asset_key) < MIN_KEY_LEN:
            raise MarkError("SHORT_KEY", "asset key must be >= 32 bytes")
        if profile.code_bits % 2:
            raise MarkError("BAD_PROFILE", "code_bits must be even")
        self.p = profile
        pb = bytes([profile.pid])
        self._k_prp = _sub(asset_key, b"prp" + pb)
        self._k_chk = _sub(asset_key, b"check" + pb)
        self._k_wht = _sub(asset_key, b"whiten" + pb)
        self._k_bnd = _sub(asset_key, b"bind" + pb)

    # ---- keyed permutation of the index (balanced Feistel, KMAC256 round function) ----
    def _round(self, r: int, half: int) -> int:
        h = self.p.code_bits // 2
        nbytes = (h + 7) // 8
        out = kmac256(self._k_prp, left_encode(r) + half.to_bytes(nbytes, "big"), nbytes, b"prp")
        return int.from_bytes(out, "big") & ((1 << h) - 1)

    def encode_index(self, index: int) -> int:
        n, h = self.p.code_bits, self.p.code_bits // 2
        if not 0 <= index < (1 << n):
            raise MarkError("INDEX_RANGE", f"index must be in [0, 2^{n})")
        left, right = index >> h, index & ((1 << h) - 1)
        for r in range(FEISTEL_ROUNDS):
            left, right = right, left ^ self._round(r, right)
        return (left << h) | right

    def decode_code(self, code: int) -> int:
        n, h = self.p.code_bits, self.p.code_bits // 2
        if not 0 <= code < (1 << n):
            raise MarkError("CODE_RANGE", f"code must be in [0, 2^{n})")
        left, right = code >> h, code & ((1 << h) - 1)
        for r in reversed(range(FEISTEL_ROUNDS)):
            left, right = right ^ self._round(r, left), left
        return (left << h) | right

    # ---- check tag and channel word ----
    def check(self, code: int) -> int:
        nb = (self.p.code_bits + 7) // 8
        c = self.p.check_bits
        tag = kmac256(self._k_chk, code.to_bytes(nb, "big"), (c + 7) // 8, b"check")
        return int.from_bytes(tag, "big") >> ((-c) % 8)

    def channel_word(self, code: int) -> int:
        return (code << self.p.check_bits) | self.check(code)

    def split_word(self, word: int):
        """(code, ok) for a channel word."""
        code = word >> self.p.check_bits
        return code, (word & ((1 << self.p.check_bits) - 1)) == self.check(code)

    def binding(self, code: int, session_id: bytes) -> bytes:
        """32-byte evidence tag binding a code to a full session TesseraID (kept in the DB)."""
        nb = (self.p.code_bits + 7) // 8
        return kmac256(self._k_bnd, code.to_bytes(nb, "big") + encode_string(session_id), 32, b"bind")

    # ---- A/B segment channel ----
    def whiten(self, segment: int) -> int:
        return kmac256(self._k_wht, segment.to_bytes(8, "big"), 1, b"whiten")[0] & 1

    def segment_bit(self, code: int, segment: int) -> int:
        """Variant (0 = A, 1 = B) of `segment` for the session holding `code`."""
        L = self.p.channel_bits
        pos = segment % L
        bit = (self.channel_word(code) >> (L - 1 - pos)) & 1
        return bit ^ self.whiten(segment)

    def sequence(self, code: int, count: int, start: int = 0):
        return [self.segment_bit(code, s) for s in range(start, start + count)]

    def decode_observations(self, observed):
        """observed: iterable of (segment, bit). Returns (code, index, agreement, erasures).

        Majority vote per channel position; uncovered or tied positions are erasures, resolved by
        trying every fill and keeping the unique one whose keyed check tag verifies.
        """
        L = self.p.channel_bits
        votes = [[0, 0] for _ in range(L)]
        obs = list(observed)
        for seg, bit in obs:
            votes[seg % L][(bit ^ self.whiten(seg)) & 1] += 1
        word, erased = 0, []
        for pos, (z, o) in enumerate(votes):
            word <<= 1
            if z == o:
                erased.append(pos)
            elif o > z:
                word |= 1
        if len(erased) > self.p.max_erasures:
            raise MarkError("TOO_MANY_ERASURES", f"{len(erased)} > {self.p.max_erasures}")
        hits = []
        for fill in range(1 << len(erased)):
            w = word
            for i, pos in enumerate(erased):
                if (fill >> i) & 1:
                    w |= 1 << (L - 1 - pos)
            code, ok = self.split_word(w)
            if ok:
                hits.append(code)
        if len(hits) != 1:
            raise MarkError("CHECK_FAILED" if not hits else "AMBIGUOUS", f"{len(hits)} candidates")
        code = hits[0]
        agree = sum(1 for s, b in obs if self.segment_bit(code, s) == b) / max(1, len(obs))
        return code, self.decode_code(code), agree, len(erased)

    def score_candidates(self, observed, codes):
        """Maximum-likelihood mode: agreement count of each allocated code with the observations."""
        obs = list(observed)
        return sorted(((sum(1 for s, b in obs if self.segment_bit(c, s) == b), c) for c in codes),
                      reverse=True)


# ---- 16-byte record: ASSET_TAG(6) || VARIANT(1) || PROFILE(1) || CODE(8) ----
def encode_record(asset_id: bytes, profile: Profile, code: int) -> bytes:
    if not 0 <= code < (1 << profile.code_bits):
        raise MarkError("CODE_RANGE")
    return asset_tag(asset_id) + bytes([VARIANT, profile.pid]) + code.to_bytes(8, "big")


def decode_record(raw: bytes):
    """Returns (asset_tag, profile, code). Structural validation only (no key needed)."""
    if len(raw) != RECORD_LEN:
        raise MarkError("INVALID_LEN", f"{len(raw)} != {RECORD_LEN}")
    if raw[6] != VARIANT:
        raise MarkError("UNKNOWN_VARIANT", f"0x{raw[6]:02x}")
    p = PROFILES.get(raw[7])
    if p is None:
        raise MarkError("UNKNOWN_PROFILE", f"0x{raw[7]:02x}")
    code = int.from_bytes(raw[8:], "big")
    if code >> p.code_bits:
        raise MarkError("NONCANONICAL", "bits above code_bits must be zero")
    return raw[:6], p, code


# ---- human text form: TM32-<crockford code>-<mod-37 check> ----
def _b32(value: int, nbits: int) -> str:
    nch = (nbits + 4) // 5
    value <<= nch * 5 - nbits
    return "".join(_CROCKFORD[(value >> (5 * (nch - 1 - i))) & 31] for i in range(nch))


def to_text(profile: Profile, code: int) -> str:
    body = _b32(code, profile.code_bits)
    check = _CROCKFORD[((profile.pid << profile.code_bits) | code) % 37]
    return f"{profile.name}-{body}-{check}"


def from_text(text: str):
    t = text.strip().upper().replace("O", "0").replace("I", "1").replace("L", "1")
    try:
        name, body, check = t.split("-")
    except ValueError as e:
        raise MarkError("BAD_TEXT", "expected PROFILE-CODE-CHECK") from e
    p = BY_NAME.get(name)
    if p is None or len(body) != (p.code_bits + 4) // 5 or len(check) != 1:
        raise MarkError("BAD_TEXT", "unknown profile or wrong length")
    value = 0
    for ch in body:
        d = _CROCKFORD.find(ch)
        if not 0 <= d < 32:
            raise MarkError("BAD_TEXT", f"bad symbol {ch!r}")
        value = (value << 5) | d
    pad = len(body) * 5 - p.code_bits
    if value & ((1 << pad) - 1):
        raise MarkError("NONCANONICAL", "non-zero pad bits")
    code = value >> pad
    if _CROCKFORD[((p.pid << p.code_bits) | code) % 37] != check:
        raise MarkError("BAD_CHECK", "text check symbol mismatch")
    return p, code
