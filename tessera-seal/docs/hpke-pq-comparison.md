# TesseraSeal vs HPKE-PQ — a one-page comparison

**Date:** 2026-06-10 · **Status:** decision record, **non-normative**. **Tickets:** TP-145 / TESS-00018.

HPKE (RFC 9180, <https://www.rfc-editor.org/rfc/rfc9180>) with the post-quantum KEM registrations in
draft-ietf-hpke-pq (rev -04 at time of writing, <https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>) is the
ecosystem's standards-track answer to post-quantum public-key encryption. TesseraSeal overlaps it deliberately. This
page records why TesseraSeal exists anyway, and when you should pick each. Reviewers ask these three questions first;
here are the written answers.

## 1. Key commitment — TesseraSeal ships it, HPKE ships none

Every TesseraSeal envelope — including hybrid `0x06` — carries a **32-byte UtC commitment tag** (Bellare–Hoang UtC,
<https://eprint.iacr.org/2022/268>). HPKE's registered AEADs (AES-GCM, ChaCha20-Poly1305) are known to be
non-key-committing (Len–Grubbs–Ristenpart, <https://eprint.iacr.org/2020/1491>), and neither RFC 9180 nor
draft-ietf-hpke-pq adds a commitment mechanism. In multi-recipient or attacker-supplied-key settings, a
non-committing AEAD admits envelopes that decrypt to different valid plaintexts under different keys; the UtC tag
closes that class structurally. If your threat model includes malicious senders or cross-key confusion, this is the
deciding row.

## 2. Error-oracle discipline — normative in TesseraSeal, implementation-defined in HPKE

TesseraSeal's spec mandates a **single `DecryptionError` class** for every authentication-class failure (bad AEAD
tag, bad commit tag, bad KEM ciphertext, AD mismatch) in all eight reference implementations, with constant-time
failure paths as a normative goal (see [side-channel-disclaimer.md](side-channel-disclaimer.md) for the honest
limits). RFC 9180 defines abstract errors (`OpenError`, `ValidationError`, …) but leaves the observable error
surface to each implementation — distinguishing-oracle hygiene is a per-library property, not a guarantee of the
standard.

## 3. Wire format — fixed 16-byte polyglot header vs HPKE's flexibility

HPKE is an *API and scheme*, not an envelope: it defines `Seal`/`Open` and an `enc` value, and applications design
their own framing, ciphersuite signaling, and AD conventions. Its registries (KEMs × KDFs × AEADs, growing with the
PQ draft) give real agility — and a combinatorial interop matrix. TesseraSeal is the opposite trade: a **frozen
16-byte header** (`TS ‖ VAR ‖ SUITE ‖ CTR ‖ KEM_CT_LEN ‖ AD_LEN`), exactly three allocated suites, decoders that
reject everything else, and a cross-language KAT contract proving the same bytes decrypt identically in every port.
An envelope written today is a self-describing at-rest artifact with one possible interpretation.

## When to choose which

Choose **HPKE / HPKE-PQ** when:

- you need an IETF standard, or interop with HPKE-consuming protocols (MLS, TLS ECH, OHTTP);
- you want ecosystem hybrid interop (X-Wing / ML-KEM-768 — see [xwing-divergence.md](xwing-divergence.md));
- you need suite agility, streaming via the export API, or single-shot APIs already shipped in mainstream libraries;
- key commitment is not in your threat model, or you layer it yourself.

Choose **TesseraSeal** when:

- you need a **committing** post-quantum envelope off the shelf (HPKE's documented gap);
- you are storing artifacts at rest and want one fixed wire format, byte-identical across 8 languages, KAT-pinned;
- you want the single-error-class oracle discipline as a spec property rather than a library accident;
- you want CNSA 2.0 parameter alignment (ML-KEM-1024 in every suite — see
  [policy-profiles.md](policy-profiles.md));
- you use the TesseraID-as-AD binding pattern with the rest of the Tessera family.

Honest closing note: HPKE-PQ will be the default choice for most protocol work once its RFC lands, and age already
ships native post-quantum recipients for file encryption. TesseraSeal's defensible niche is the conjunction of
key commitment + frozen polyglot wire + single-oracle discipline — not post-quantum encryption per se. When an
HPKE-PQ profile with mandatory key commitment appears, this comparison must be rewritten.
