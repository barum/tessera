# TesseraMark — Rationale (v1)

## 1. Name
**TesseraMark**: in the tessera family, *ID* identifies, *Hash* addresses content, *Seal*
encrypts, *Mark* is what you stamp into the work. "Watermark" alone is too broad (the format is the
payload, not the embedder); "Serial" suggests sequence, which is exactly what we remove. Alternatives
considered: TesseraTrace, TesseraTag, TesseraSerial. Name clearance would follow
`docs/decisions/2026-06-10-name-clearance.md`.

## 2. The constraint
The A/B channel carries ~1 bit per segment. Lockitdown today (`crates/ld-watermark`, migration
0035) embeds a 32-bit **sequential** serial + CRC-16 = 48 bits, repeated `mod 48`, majority-voted.
It works, but serials are predictable (1, 2, 3…), leak the number of sessions per asset, and the
CRC is unkeyed (anyone can build a valid word).

| Option | Bits embedded | Time @2 s (1 cycle) | Problem |
|---|---|---|---|
| TesseraID directly | 328 | 10.9 min | far too long; timestamp leaks session start |
| UUIDv7 | 128 | 4.3 min | too long; 48-bit timestamp leaks; only 74 random bits |
| Sequential serial (today) | 32+16 | 96 s | predictable, counts sessions, unkeyed CRC |
| Random-with-lookup, 32 bits | 32+16 | 96 s | birthday: P(collision) ≈ 1 at 10⁶ sessions; must retry/check uniqueness |
| Random-with-lookup, 64 bits | 64+16 | 2.7 min | collisions fine, but 67 % longer than needed |
| HMAC(session) truncated to n | n+c | as profile | not invertible, collisions as random-with-lookup |
| **TesseraMark (keyed PRP of index)** | n+c | as profile | none of the above; needs key at decode |

Birthday numbers (random-with-lookup, `N²/2^(n+1)`): 32 bits → 1.2e-2 at 10⁴, ≈1 at 10⁶; 40 bits →
0.45 at 10⁶; 48 bits → 1.8e-3 at 10⁶. A permutation has zero collisions, so TM32 serves up to 4.3e9
sessions per asset with no uniqueness retry.

## 3. Threat model
- **Enumeration**: an attacker with their own copy sees one code. A keyed PRP over 2ⁿ indices is
  indistinguishable from random to anyone without `K_prp`, so neither order nor count leaks.
- **Framing (forging a mark that decodes to a victim)**: must produce a word whose keyed check
  verifies *and* whose code is allocated: `2^-c · N/2^n` per attempt (3.6e-9 for TM32, N=10⁶).
  Each attempt costs a full leaked stream and an operator-run decode, so attempts are few. A
  framing accusation is also contested by the low-level evidence (agreement score, capture), and a
  single decode is never sufficient for a legal claim (policy: require agreement ≥ τ and corroboration).
- **Noise / partial capture**: repetition across cycles, majority per position, erasures resolved
  by keyed-check search (each erasure spends one check bit, hence `e_max = c − 12`), then ML scoring
  over the candidate set as fallback.
- **Collusion**: two or more viewers mixing segments produce a word that typically fails the check
  (detected, not traced). v0.1 is honest about this; the Tardos profile (§5) traces but is slow.
- **Cross-asset replay**: keys are per asset (+ TesseraHash), whitening differs, ATAG differs.
- **Insider tampering**: binding tag + lockitdown's hash-chained audit log.

## 4. Why a Feistel over KMAC256 rather than FF1
- tessera's discipline is one primitive family (Keccak/SHAKE) across 8 languages; KMAC256 is
  already implementable everywhere tessera-hash runs. FF1 pulls in AES and a fiddly numeral-string
  spec with known implementation bugs (Bleichenbacher's floating-point bug noted by NIST).
- FF3/FF3-1 are out: the SP 800-38G Rev. 1 2nd public draft (Feb 2025) removes FF3 (incl. FF3-1)
  after Beyne's tweak-schedule attack. As of Oct 2026 Rev. 1 is still a draft and SP 800-38G (2016)
  remains the final publication, so FF1 is the only NIST-approved FPE.
- Known small-domain FPE attacks (Bellare–Hoang–Tessaro 2016; Durak–Vaudenay 2017; Hoang–Tessaro–
  Trieu 2018) need many chosen/known plaintext–ciphertext pairs under related tweaks. Here the
  adversary learns at most a handful of codes (their own or their colluders') and never an index.
  12 rounds (FF1 uses 10) is a conservative margin. A FIPS profile can swap in FF1 radix 2.

## 5. Collusion-resistant layer: honest length
`m = A c₀² ln(N/ε)` with ε = 10⁻³, N = 10⁶ (`ln ≈ 20.7`):

| c₀ | Tardos A=100 | symmetric A=π² (provable) | Gaussian A=π²/2 | capacity A=2 |
|---|---|---|---|---|
| 2 | 8,290 b (4.6 h @2 s) | 819 b (27 min @2 s; 82 min @6 s) | 410 b (14 min; 41 min) | 166 b (5.5 min; 17 min) |
| 3 | 18,651 b (10.4 h) | 1,841 b (61 min; 3.1 h) | 921 b (31 min; 92 min) | 374 b (12.5 min) |
| 4 | 33,158 b (18.4 h) | 3,273 b (1.8 h; 5.5 h) | 1,637 b (55 min; 2.7 h) | 664 b (22 min) |
| 8 | 132,629 b (74 h) | 13,090 b (7.3 h) | 6,545 b (3.6 h) | 2,653 b (88 min) |

Conclusion: collusion tracing cannot meet a 1–2 minute live-sports target at 1 bit/segment. Use
TM32 for live takedown, and a Tardos profile for VOD/after-the-fact forensics. Getting more bits per
second (CMAF chunk-level A/B at 0.5–1 s, or partner embedders carrying several bits per segment)
is the real lever and should be raised with embedding partners.

## 6. Post-quantum
- All keys ≥ 256 bits; KMAC256 has 256-bit security classically, ≥128-bit under Grover.
- Short tags (12–16 check bits) stay acceptable because verification is **online only**: Grover
  needs an oracle that evaluates the predicate in superposition, which requires the key. Without it
  the attacker submits candidate leaks to the operator one at a time, i.e. classical guessing at
  `2^-c · N/2^n` per try. A quantum computer gives no speedup on that.
- Key recovery from observed codes is a 256-bit key search (≥ 2¹²⁸ quantum).
- The record and binding tags are stored, not transmitted; long-term confidentiality of the
  allocation table (exports, backups) should use TesseraSeal (ML-KEM-1024).

## 7. Lookup vs. "decryptable" codes
Inverting the PRP yields the index without a search, so decode is O(1) in the number of sessions and
needs no reverse index over codes. You still need one primary-key lookup (index → session
TesseraID), and that is deliberate: the 41-byte TesseraID cannot fit, and keeping the mapping
server-side means a stolen key alone does not reveal identities. Random-with-lookup needs a
unique index on `code` plus collision retries.

## 8. Lockitdown adoption (proposal; not implemented)
Migration `0036_tessera_mark.sql` (sketch):
```sql
ALTER TABLE watermark_marks ADD COLUMN profile smallint NOT NULL DEFAULT 2,  -- TM32
                            ADD COLUMN mark_epoch integer NOT NULL DEFAULT 1;
-- next_serial becomes next_index (allocation order, never embedded)
CREATE TABLE watermark_allocations (
    tenant_id  uuid NOT NULL DEFAULT ld_current_tenant(),
    asset_id   uuid NOT NULL,
    profile    smallint NOT NULL,
    mark_index bigint NOT NULL,            -- PRP input
    code       bigint NOT NULL,            -- PRP output (TM32/40/48; TM64 needs numeric/bytea)
    session_tid bytea NOT NULL CHECK (octet_length(session_tid) = 41),
    binding    bytea NOT NULL CHECK (octet_length(binding) = 32),
    subject text NOT NULL, session_id text NOT NULL, device_id text,
    issued_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, asset_id, profile, mark_index),
    UNIQUE (tenant_id, asset_id, profile, code),
    UNIQUE (tenant_id, asset_id, subject, session_id)
);  -- + RLS tenant_isolation as in 0035
```
- **License time** (`ld-license decide`): in the same transaction, `UPDATE watermark_marks SET
  next_index = next_index + 1 RETURNING` → `code = PRP(index)`, mint session TesseraID, store binding.
  Response header `LD-Watermark-Serial` becomes `LD-Watermark-Mark: TM32-…-…` (text form).
- **Decode endpoint** (`POST …/watermark/decode`): direct decode → index → row → verify binding;
  on `CHECK_FAILED`, ML scoring over sessions live in the capture window; returns code text,
  agreement, erasures, session TesseraID; audited `watermark.decoded`.
- **Migration from sequential serials**: existing rows keep `profile = legacy (0x00 local)` and the
  old decoder; new sessions get TesseraMark. No re-packaging: A/B variants are unchanged, only the
  per-session sequence changes. Deprecate legacy after the longest license TTL.
- Lockitdown currently uses UUID PKs; TesseraID `bytea(41)` for session ids is the separate
  ID-migration discussed with the owner and is not required to adopt TesseraMark.

## 9. Open questions for the owner
1. Default profile: TM32 (96 s clean @2 s) vs TM40 for assets expecting > 10⁷ sessions?
2. Accept a 4th variant byte `0x05` for a 16-byte *record* even though the embedded payload has
   no variant byte? (Alternative: TesseraMark is a sub-format inside a TesseraHash-style record.)
3. KMAC-Feistel only, or also a FIPS FF1 profile?
4. Priority of coded (BCH/RS) and Tardos profiles; and whether partners can offer multi-bit
   segments or sub-segment chunk marking.
5. Legal posture: what agreement threshold and corroboration counts as an accusation.

## Adopted defaults (2026-10-23)

- **Default profile TM32.** Fastest safe identification (96 s clean at 2 s segments) with
  `P_fa ≈ 3.6e-9` at 10⁶ sessions. Deployments SHOULD move an asset to **TM40** automatically as
  its allocated sessions approach 10⁷ (new allocations only; existing TM32 marks stay decodable,
  since the profile byte is part of every record).
- **Variant byte `0x05`**, used only in the 16-byte storage record.
- **PRP:** KMAC Feistel by default; FF1 (AES-256) available as an opt-in FIPS mode (SPEC §4.1.1).
- **Accusation** per SPEC §5.5: `< 10⁻⁹` false-match probability, keyed check on ≥ 2 independent
  captures, and a verified stored binding tag; anything weaker goes to human review.
