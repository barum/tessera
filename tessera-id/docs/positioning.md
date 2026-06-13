# TesseraID positioning: a sortable capability ID

**Date:** 2026-06-10 · **Status:** decision record, **non-normative** (the wire format is normative in the
[whitepaper](../../TesseraID_Whitepaper.pdf); this page positions it). **Tickets:** TP-133 (doc part) / TESS-00018.

TesseraID's strongest claim is not "post-quantum ID" — Grover's algorithm is largely irrelevant to online identifier
guessing. The defensible position is **sortable capability ID**: a time-sortable identifier whose random tail is
strong enough that mere possession can safely grant access. This page states that position, the honest costs, and
when you should *not* use TesseraID.

## The gap RFC 9562 documents itself

The UUID standard's own Security Considerations say it plainly: implementations SHOULD NOT assume UUIDs are hard to
guess, and UUIDs "MUST NOT be used as security capabilities (identifiers whose mere possession grants access)"
(RFC 9562 §8, <https://www.rfc-editor.org/rfc/rfc9562#section-8>).

The arithmetic behind that disclaimer for UUIDv7: the layout is a 48-bit ms timestamp plus **74 random bits**
(`rand_a` 12 + `rand_b` 62, RFC 9562 §5.7, <https://www.rfc-editor.org/rfc/rfc9562#section-5.7>) — and the optional
monotonic-counter methods of §6.2 spend some of those 74 bits on a counter. A creation timestamp is routinely
observable or guessable to the millisecond, so the effective secret is at most 2^74 — far below the ~128-bit floor
expected of bearer secrets. TesseraID's tail is **256 random bits** from the OS CSPRNG: capability-grade with margin,
even under the conservative Grover-style accounting (~128-bit post-quantum) the whitepaper uses.

Among portable sortable formats, nothing else occupies this point:

| Format | Random bits | Timestamp precision | Distributed-causality story |
|--------|-------------|---------------------|------------------------------|
| UUIDv7 (<https://www.rfc-editor.org/rfc/rfc9562>) | ≤ 74 | 1 ms | none |
| ULID (<https://github.com/ulid/spec>) | 80 (monotonic mode makes same-ms successors predictable) | 1 ms | none |
| KSUID (<https://github.com/segmentio/ksuid>) | 128 | 1 s | none |
| TypeID (<https://github.com/jetify-com/typeid>) | ≤ 74 (UUIDv7 inside) | 1 ms | none |
| **TesseraID** | **256** | 1 ms | **normative HLC variant, fixed 60 s drift bound** |

The HLC half of the claim is the second unique point: TesseraID is the only portable ID format with a normative
Hybrid Logical Clock variant — fixed merge rule, fixed hard-reject drift bound, identical in eight languages. The
field-level mappings to CockroachDB, MongoDB, uhlc-rs, and Dart `crdt` are in [hlc-interop.md](hlc-interop.md).

## The honest cost: 41 bytes vs 16

TesseraID is 2.56× the size of a UUID. That cost is real and multiplies through B-tree indexes. Raw key bytes per
index (key column only — arithmetic, **not** a measured benchmark):

| Rows  | UUID (16 B) | TesseraID (41 B) | Delta per index |
|-------|-------------|------------------|-----------------|
| 10^7  | 160 MB      | 410 MB           | +250 MB         |
| 10^8  | 1.6 GB      | 4.1 GB           | +2.5 GB         |
| 10^9  | 16 GB       | 41 GB            | +25 GB          |

Per-entry estimates with engine overhead (still arithmetic):

- **PostgreSQL B-tree leaf entry**: 4 B line pointer + 8 B index-tuple header + key. `uuid` (fixed 16 B) ≈
  4 + 8 + 16 = **28 B/entry**. TesseraID as `bytea` (1-B short varlena header + 41 B, MAXALIGNed to 48) ≈
  4 + 8 + 48 = **60 B/entry** — about **2.1×**, i.e. roughly 28 GB vs 60 GB of leaf entries at 10^9 rows, before
  page overhead and fillfactor. Postgres secondary indexes point at heap tuples via 6-byte TIDs, **not** via the PK,
  so the inflation hits the PK index and any foreign-key columns (each referencing row + its indexes), not every
  secondary index.
- **MySQL/InnoDB**: the PK is the clustered key and is **appended to every secondary index entry**, so each
  secondary index costs an extra 25 B × rows versus a 16-B key — with k secondary indexes at 10^9 rows, about
  k × 25 GB of additional raw key bytes.
- Directionally, fewer keys per page also means deeper/wider trees and lower buffer-pool hit rates; quantifying that
  honestly requires measurement. **Measured database benchmarks (insert throughput, cache behavior, WAL volume) are
  future work** — no such numbers are claimed here or anywhere in the Tessera docs.

## When NOT to use TesseraID

Use UUIDv7 for ordinary primary keys. Specifically, prefer UUIDv7 when:

- IDs never leave your trust boundary and never act as access-granting handles — the 256-bit tail buys nothing;
- you want the native 16-byte `uuid` column type, now with server-side generation (`uuidv7()` in PostgreSQL 18,
  <https://www.postgresql.org/docs/18/functions-uuid.html>) and first-class ORM/driver support everywhere;
- the table is hot and heavily secondary-indexed on InnoDB, where the clustered-key multiplication above bites;
- your ecosystem assumes 128-bit IDs (schema registries, existing uuid-typed APIs).

Use TesseraID when the identifier **is** the credential surface (unguessable object keys, share links, API resource
handles served to untrusted parties), when you need sortable IDs plus capability strength in one value instead of an
ID + token pair, or when you need the HLC variant's cross-node causality with a hard drift bound.

## TesseraID for UUIDv7 users — migration sketch

Coexistence beats migration. The pattern that avoids almost all of the cost table above:

1. **Keep the uuid PK internal.** Joins, FKs, and secondary indexes stay 16-byte. Add a `BYTEA` / `BINARY(41)`
   unique column (or a 55-char Base64URL text column) holding a TesseraID only for resources whose identifiers are
   exposed across a trust boundary.
2. **Dual-write going forward; backfill lazily.** There is no deterministic UUIDv7 → TesseraID function — the
   256-bit tail is random by construction — so the mapping is a column, not a formula.
3. **Pagination keeps working.** Both formats lead with a 48-bit ms timestamp; keyset pagination on
   (extracted-timestamp, id) stays correct across mixed populations.
4. **Expose text forms at the edge**: canonical 55-char Base64URL, or 66-char Crockford where humans type IDs
   (see [../README.md](../README.md) for both encodings and their decode guards).
5. **Planned, not shipped**: a lossy TesseraID → UUIDv8 down-mapping profile (remediation item TP-134) for
   uuid-typed views over TesseraID-keyed data. Until it lands, the dual-column pattern above is the supported route.

For the capability-ID threat model in depth (why 74 bits with a public timestamp fails as a bearer secret, CSPRNG
sourcing rules, encoding malleability guards), see the whitepaper's security sections — and for the encryption-side
sibling of this positioning argument, TesseraSeal's [policy profiles](../../tessera-seal/docs/policy-profiles.md).
