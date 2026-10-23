# TesseraMark — Keyed Compact Forensic Mark (v1)

> **Status: v1, 2026-10-23, under review.** Allocates variant byte `0x05` in the shared tessera
> namespace. TesseraID, TesseraHash and TesseraSeal decoders already reject `0x05` (their
> `invalid.json` vectors cover it). Reference implementations: Rust, TypeScript, Python.

Key words MUST, SHOULD, MAY are per RFC 2119 / RFC 8174.

## 1. What it is

A TesseraMark is a **short (24–64 bit) keyed code** carried in a low-bandwidth forensic channel
(A/B segment watermarks, audio marks, image marks, text/whitespace marks). It is:

- **Bound** to a full TesseraID (the session/license) and to its asset (TesseraID, optionally
  TesseraHash) via a server-side index and a 256-bit binding tag.
- **Unique per asset by construction**: it is a keyed *permutation* of an allocation index, so no
  two sessions of one asset can collide (no birthday bound).
- **Non-sequential and unlinkable**: without the asset key, codes look uniformly random; they
  reveal neither issue order nor session counts, and the same index on two assets gives unrelated
  codes.
- **Authenticated**: a keyed check tag makes forged or noise-produced words fail with probability
  `1 − 2^-c` before any lookup.
- **Invertible**: the key holder recovers the allocation index directly (no search); one indexed
  row lookup maps it to the session TesseraID.

It is **not** an identifier for general use (use TesseraID), not a content hash (TesseraHash), and
not encryption (TesseraSeal). The embedded payload never carries a variant byte; the variant byte
appears only in the 16-byte **record** form (§6) used for storage, export and evidence.

## 2. Profiles

| Profile | PROFILE byte | code `n` | check `c` | channel word `L = n + c` | max erasures `e_max = c − 12` | Target |
|---|---|---|---|---|---|---|
| TM24 | `0x01` | 24 | 12 | 36 | 0 | small VOD, screener lists (≤ 10⁴ sessions/asset) |
| TM32 | `0x02` | 32 | 16 | 48 | 4 | **default**; live sports at 2 s segments |
| TM40 | `0x03` | 40 | 16 | 56 | 4 | ≥ 10⁷ sessions/asset |
| TM48 | `0x04` | 48 | 16 | 64 | 4 | very large / long-lived assets |
| TM64 | `0x05` | 64 | 16 | 80 | 4 | images, documents, text (no time pressure) |

`0x00`, `0xFF` permanently reserved; `0x06`–`0x0F` reserved for coded profiles (§5.3, §5.4);
`0x10`–`0xFE` reserved-future. Decoders MUST reject unknown PROFILE bytes (`UNKNOWN_PROFILE`).
`n` MUST be even (balanced Feistel). The index space is `[0, 2^n)`; implementations SHOULD start at a
random offset or 0 — the permutation hides order either way.

## 3. Keys (single primitive: KMAC256, NIST SP 800-185)

All keyed functions are KMAC256 [SP800-185 §4]; `encode_string`/`left_encode` are SP 800-185 §2.3.

```
K_master : >= 32 bytes, per tenant, held by the key service (HSM-wrapped)
K_asset  = KMAC256(K_master, encode_string(tenant) || encode_string(asset_TesseraID)
                              || encode_string(asset_TesseraHash or ""), 256, "TesseraMark v1 asset key")
K_x      = KMAC256(K_asset, x || PROFILE, 256, "TesseraMark v1 subkey")   for x in
           {"prp", "check", "whiten", "bind"}
```

Keys shorter than 32 bytes MUST be rejected (`SHORT_KEY`). Binding the TesseraHash makes a
re-encoded or substituted asset a different key domain (anti-replay across assets, §8).
Lockitdown MAY instead store a random 32-byte `K_asset` wrapped under the tenant KEK (as migration
0035 already does); the derivation above is the default when only a tenant key exists.

## 4. Construction

### 4.1 Code = keyed permutation of the index
Balanced Feistel, `R = 12` rounds, halves of `h = n/2` bits, `B = ceil(h/8)`:
```
(Lft, Rgt) = (index >> h, index mod 2^h)
for r in 0..R-1:
    F = KMAC256(K_prp, left_encode(r) || I2OSP(Rgt, B), 8B, "prp") as integer, masked to h bits
    (Lft, Rgt) = (Rgt, Lft XOR F)
code = (Lft << h) | Rgt
```
Decode runs the rounds in reverse.

### 4.1.1 FF1 mode (optional, FIPS deployments)
The PRP MAY instead be FF1 [SP800-38G §5.1] with AES-256, radix 2, numeral string = the `n` code
bits MSB first, tweak = the single PROFILE byte, and key
`K_ff1 = KMAC256(K_asset, "ff1" || PROFILE, 256, "TesseraMark v1 subkey")`. The domain is
`2^n ≥ 2^24 ≥ 10⁶`, satisfying the Rev. 1 draft minimum. The mode is **not** carried in the record:
a deployment stores it next to the asset key and key epoch, and KMAC Feistel is the default.
Check tag, whitening, binding and record are identical in both modes. FF3/FF3-1 MUST NOT be used
(removed in the SP 800-38G Rev. 1 2nd public draft). Vectors: `conformance/vectors/ff1.json`; the
FF1 core is pinned to NIST SP 800-38G samples 7–9.

### 4.2 Check tag and channel word
```
check = first c bits of KMAC256(K_check, I2OSP(code, ceil(n/8)), ceil(c/8)*8, "check")
word  = code || check          (L bits, MSB first)
```

### 4.3 Binding tag (server side, never embedded)
```
bind = KMAC256(K_bind, I2OSP(code, ceil(n/8)) || encode_string(session_TesseraID), 256, "bind")
```
Stored with the allocation row; recomputed at decode time to show the row was not edited after
issuance by anyone without the key (combine with lockitdown's hash-chained audit for full evidence).

### 4.4 A/B segment channel
Segment `s` (absolute media-timeline index) carries word bit `pos = s mod L`, XOR a keyed whitening
bit:
```
w(s)        = KMAC256(K_whiten, I2OSP(s, 8), 8, "whiten")[0] & 1
variant(s)  = word[pos] XOR w(s)            (0 = A, 1 = B)
```
Whitening makes the A/B sequence key-dependent so colluders cannot read positions directly and two
assets never share patterns.

## 5. Decoding

### 5.1 Direct decode (no candidate set)
1. For each observed `(s, v)`: vote `v XOR w(s)` at `s mod L`.
2. Majority per position; uncovered or tied positions are **erasures**. If erasures > `e_max`:
   `TOO_MANY_ERASURES`.
3. Try all `2^e` fills; keep fills whose `check` verifies. Exactly one → success; none →
   `CHECK_FAILED`; more than one → `AMBIGUOUS`.
4. `index = PRP⁻¹(code)`; look up `(tenant, asset, profile, index)` → session TesseraID; verify `bind`.
5. Report agreement = matching observations / observations.

False accept per decode attempt (garbage or forgery reaches an *allocated* session):
`P_fa ≈ 2^(e − c) · N / 2^n` for `N` allocated sessions.

### 5.2 Maximum-likelihood decode (candidate scoring)
When the candidate set is small (e.g. sessions concurrently live for that event), score every
allocated code by agreement with the observations and accuse only above a threshold `τ`. Union
bound: `P_false ≤ N · P[Bin(m, 1/2) ≥ τm]`. This tolerates heavy noise but needs more segments
(see table). It is the recommended mode once direct decode fails.

### 5.3 Coded profiles (reserved `0x06`–`0x0B`, not in v0.1)
Outer error-correcting codes over the word (e.g. shortened BCH or RS over GF(2⁸) with erasure
decoding) trade channel bits for burst/noise tolerance. v0.1 relies on repetition across cycles +
majority + keyed-check erasure search, which is what the prototype implements. A coded profile is
only added with its own vectors.

### 5.4 Collusion-resistant profile (reserved `0x0C`–`0x0F`, not in v0.1)
A binary Tardos-family code [Tardos 2003; Škorić et al. 2008] whose per-user codeword is generated
from `KMAC256(K_tardos, index ...)` replaces the word. Length is `m = A · c₀² · ln(N/ε)` bits
(A = 100 original; π² provable symmetric; π²/2 Gaussian approx.; asymptotic limit 2). These are
**minutes to hours** of video (RATIONALE §5), so it is a forensic-after-the-fact profile, not a
live-takedown one.

### 5.5 Accusation policy (normative for automated actions)
An implementation that triggers external action (takedown, account action) MUST require all of:
(a) false-match probability `< 10⁻⁹`, computed as the §5.2 union bound over the full candidate set
(`false_match_probability(N, m, agreements)` in the reference implementations); (b) the keyed check
passing on **at least two independent captures**; (c) a stored binding tag (§4.3) that verifies.
Anything weaker is flagged for human review and MUST NOT trigger an automatic action.

## 6. Record wire format (16 bytes)

```
offset  0      6        7        8                         16
        | ATAG(6) | VARIANT | PROFILE | CODE (8, big-endian) |
ATAG    = SHAKE256("TesseraMark v1 asset tag" || encode_string(asset_TesseraID), 48 bits)
VARIANT = 0x05
```
Matches the tessera convention: variant byte at offset 6. Bits of CODE above `n` MUST be zero
(`NONCANONICAL`). Length ≠ 16 → `INVALID_LEN`; VARIANT ≠ `0x05` → `UNKNOWN_VARIANT` (and every other
tessera decoder MUST reject `0x05`). ATAG is public routing data, not a secret.

Encodings: record → Base64URL (22 chars) or Crockford Base32 (26 chars; low 2 pad bits MUST be 0).

## 7. Human text form (for incident reports and legal exhibits)

`<PROFILE>-<Crockford Base32 of code, ceil(n/5) chars>-<check symbol>` e.g. `TM32-00030E8-1`.
The check symbol is Crockford's mod-37 symbol (`0-9A-Z*~$=U` minus ILOU in the 32 data symbols) over
`(PROFILE << n) | code`. Decode is case-insensitive with `I/L→1`, `O→0`; non-zero pad bits are rejected.

## 8. Threat model (summary; detail in RATIONALE §3)

| Threat | Mitigation | Residual |
|---|---|---|
| Enumeration / counting sessions | keyed PRP: codes are a pseudorandom permutation of indices | none without `K_asset` |
| Guess a valid mark to frame someone | keyed check (`2^-c`) × sparse allocation (`N/2^n`); accusation also requires the observed sequence | `P_fa` table §9 |
| Learn other users' marks from own copy | own copy reveals only own code; PRP/whitening are keyed | none |
| Replay a mark across assets | `K_asset` binds asset TesseraID (+ TesseraHash); ATAG in record | — |
| Partial / noisy capture | majority over cycles, erasure search, ML scoring | longer capture needed |
| Collusion (mix segments) | v0.1: detected as low agreement / CHECK_FAILED, not traced | needs §5.4 profile |
| Quantum adversary | 256-bit keys, KMAC256 (≥128-bit PQ); tags verifiable only online | see RATIONALE §6 |
| Insider edits allocation row | `bind` tag + hash-chained audit | key holder trust |

## 9. Profile numbers (from `python/analysis.py`)

Time to identify = channel bits × segment duration (1 bit/segment). "Clean" = one full cycle with
no errors; "robust" = 3 cycles (majority survives ~1 error per position).

| Profile | L | clean @2 s | clean @4 s | clean @6 s | robust @2 s | robust @6 s | P_fa N=10⁶ | P_fa N=10⁷ |
|---|---|---|---|---|---|---|---|---|
| TM24 | 36 | 72 s | 2.4 min | 3.6 min | 3.6 min | 10.8 min | 1.5e-05 | 1.5e-04 |
| TM32 | 48 | 96 s | 3.2 min | 4.8 min | 4.8 min | 14.4 min | 3.6e-09 | 3.6e-08 |
| TM40 | 56 | 112 s | 3.7 min | 5.6 min | 5.6 min | 16.8 min | 1.4e-11 | 1.4e-10 |
| TM48 | 64 | 2.1 min | 4.3 min | 6.4 min | 6.4 min | 19.2 min | 5.4e-14 | 5.4e-13 |
| TM64 | 80 | 2.7 min | 5.3 min | 8.0 min | 8.0 min | 24.0 min | 8.3e-19 | 8.3e-18 |

Code collisions within an asset: **0** for every profile (permutation).

## 10. Errors

`SHORT_KEY`, `BAD_PROFILE`, `INDEX_RANGE`, `CODE_RANGE`, `INVALID_LEN`, `UNKNOWN_VARIANT`,
`UNKNOWN_PROFILE`, `NONCANONICAL`, `TOO_MANY_ERASURES`, `CHECK_FAILED`, `AMBIGUOUS`, `BAD_TEXT`,
`BAD_CHECK`. Errors MUST NOT reveal which check failed beyond these codes.

## 11. API sketch (mirrors tessera-id / tessera-hash shape)

Rust:
```rust
pub enum Profile { Tm24, Tm32, Tm40, Tm48, Tm64 }
pub struct AssetKey(Zeroizing<[u8; 32]>);
impl AssetKey { pub fn derive(master: &[u8], tenant: &[u8], asset: &TesseraId, hash: Option<&TesseraHash>) -> Result<Self, MarkError>; }
pub struct Mark { /* subkeys */ }
impl Mark {
    pub fn new(key: &AssetKey, p: Profile) -> Self;
    pub fn encode_index(&self, index: u64) -> Result<Code, MarkError>;
    pub fn decode_code(&self, code: Code) -> Result<u64, MarkError>;
    pub fn binding(&self, code: Code, session: &TesseraId) -> [u8; 32];
    pub fn segment_variant(&self, code: Code, segment: u64) -> Variant;
    pub fn decode_observations(&self, obs: &[(u64, Variant)]) -> Result<Decoded, MarkError>;
}
pub struct Record([u8; 16]);   // from_bytes / to_bytes / to_text / from_text / validate
```
TypeScript: `Mark.create(assetKey, "TM32")`, `encodeIndex(bigint)`, `decodeCode(bigint)`,
`segmentVariant(code, segment)`, `decodeObservations(obs)`, `Record.fromBytes/ toText/ fromText`;
codes are `bigint`. Error names match §10.

## 12. Conformance vectors

`conformance/vectors/`: `context.json` (fixed master key, tenant, asset TesseraID/Hash, derived key,
ATAG), `allocate.json` (per profile: index 0, 1, 2, 1000, 2ⁿ−1 → code, check, word, text, record,
binding, first 16 segment variants), `ff1.json` (FF1-mode codes), `invalid.json` (cross-variant rejection `0x00–0x04, 0x06, 0xFF`,
unknown profiles, non-canonical high bits, short record). The KMAC256 primitive is pinned to the
NIST SP 800-185 sample #6 test. Adoption adds `0x05` rejection vectors to tessera-id, -hash, -seal.

## 13. Versioning

Wire changes are new PROFILE bytes or a new VARIANT, never a reinterpretation. Customization string
`"TesseraMark v1 …"` labels are frozen wire tags. Key rotation: a new `K_master` epoch is a new
`K_asset`; existing marks stay decodable with the old key (record the key epoch next to the row).

## References

- NIST SP 800-185, *SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash* (2016).
- NIST FIPS 202, *SHA-3 Standard* (2015).
- NIST SP 800-38G (2016, final) and SP 800-38G Rev. 1 2nd Public Draft (Feb 3 2025; still a draft
  per CSRC as of Oct 2026): FF3/FF3-1 removed (Beyne's tweak-schedule attack), FF1 kept, domain
  ≥ 10⁶ required. https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd
- G. Tardos, *Optimal probabilistic fingerprint codes*, STOC 2003 / J. ACM 55(2), 2008.
- B. Škorić, S. Katzenbeisser, M. Celik, *Symmetric Tardos fingerprinting codes for arbitrary
  alphabet sizes*, Des. Codes Cryptogr. 46, 2008. doi:10.1007/s10623-007-9142-x
- B. Škorić, T. Vladimirova, M. Celik, J. Talstra, *Tardos fingerprinting is better than we
  thought*, IEEE Trans. IT 54(8), 2008. doi:10.1109/TIT.2008.926307
- E. Amiri, G. Tardos, *High rate fingerprinting codes and the fingerprinting capacity*, SODA 2009;
  Y.-W. Huang, P. Moulin, *On the saddle-point solution and the large-coalition asymptotics of
  fingerprinting games*, IEEE TIFS 2012.
- L. Grover, STOC 1996; D. Crockford, *Base32* (crockford.com/base32.html).
