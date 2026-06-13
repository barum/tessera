# Why suite `0x06` is not X-Wing

**Date:** 2026-06-10 · **Status:** decision record, **non-normative**. **Tickets:** TP-145 / TESS-00018.

X-Wing (draft-connolly-cfrg-xwing-kem, <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>; design
paper <https://eprint.iacr.org/2024/039>) is the ecosystem's de-facto hybrid KEM: X25519 + **ML-KEM-768** with a
SHA3-256 combiner. TesseraSeal's hybrid suite `0x06` is X-Wing-*style* but deliberately not X-Wing. This page records
the divergence so it stops being re-litigated in every review.

## The three deliberate differences

1. **ML-KEM-1024, not 768.** Every TesseraSeal suite (`0x01`, `0x02`, `0x06`) uses the single ML-KEM-1024 parameter
   set — the CNSA 2.0 parameter (see [policy-profiles.md](policy-profiles.md)). One parameter set means one pinned,
   verified ML-KEM source per language and no parameter negotiation surface. X-Wing fixes ML-KEM-768, where the
   deployed hybrid ecosystem converged (TLS `X25519MLKEM768`, Signal's post-quantum ratchet, age's PQ recipients).
   Choosing 1024 costs interop with all of them and buys CNSA parameter alignment plus a wider Module-LWE margin.
2. **The combiner hashes both ciphertext halves.** X-Wing's combiner omits the ML-KEM ciphertext from the hash,
   relying on ML-KEM's ciphertext binding (an explicit, proven optimization in the X-Wing paper). TesseraSeal's
   combiner is the more conservative shape — SHAKE-256 over both shared secrets *and* both ciphertext halves:
   `K_session = SHAKE-256("pqcrypt v1 hybrid combiner" ‖ ss_mlkem ‖ x_ss ‖ ml_kem_ct ‖ x_eph_pk, 32)` — paying
   ~1.6 KB of extra hashing per envelope to avoid leaning on that proof.
3. **The label is a frozen wire tag.** X-Wing domain-separates with its 6-byte `\.//^\` label. TesseraSeal's label
   is the literal byte string `"pqcrypt v1 hybrid combiner"` — a **frozen v1 wire tag, not a rebrandable name**. It
   predates the PQCrypt→TesseraSeal rename and is hashed into every hybrid envelope and every hybrid KAT vector;
   it must be preserved verbatim forever (see [../CLAUDE.md](../CLAUDE.md)).

## Standards status (the timing argument)

As of 2026-03, X-Wing remains a **non-RFC individual draft** (rev -10). Adopting it wholesale would have meant
tracking a moving target inside a frozen wire format — TesseraSeal's suite bytes are append-only allocations that
cannot be revised in place. Pinning an X-Wing-style construction with our own frozen label and parameter set was the
only way to ship a hybrid in v1.2 without betting the wire format on a draft's stability.

## Revisit trigger

Reopen this decision — as a **new suite byte**, never a modification of `0x06` — when **both** hold:

1. X-Wing is published as an RFC (its combiner, label, and encodings frozen by the IETF), and
2. regulator preference shifts toward the 768-parameter hybrid (e.g. CNSA accepts ML-KEM-768, or BSI/ANSSI guidance
   names X-Wing specifically — see [policy-profiles.md](policy-profiles.md) for the current positions).

Until then, adopters who need X-Wing interop should use an HPKE stack
(see [hpke-pq-comparison.md](hpke-pq-comparison.md)); adopters who need hybrid TesseraSeal semantics
(key commitment, fixed wire, single-oracle errors) use suite `0x06` where it is implemented (Python, Go, Rust as of
v1.3 — TSEAL-00030..34 track the remaining ports).

## Related deferral: AEGIS

The other recurring "why not X?" — AEGIS-128L as a faster AEAD suite — is already recorded **in the whitepaper**, not
here: it was evaluated for v1.2 at a hypothetical suite `0x03` (PQCK-00020) and deferred because verified AEGIS
implementations were not polyglot-ready; the byte stays reserved-future. See the suites rationale in
[../latex/sec04_suites.tex](../latex/sec04_suites.tex) and the suite-allocation appendix in
[../latex/sec14_appendices.tex](../latex/sec14_appendices.tex) (RFC 9678: <https://www.rfc-editor.org/rfc/rfc9678>).
This document deliberately does not duplicate that record.
