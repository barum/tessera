# TesseraID-HLC interop with other Hybrid Logical Clock systems

**Date:** 2026-06-10 · **Status:** **non-normative** interop guidance (the HLC wire format and merge rule are
normative in the [whitepaper](../../TesseraID_Whitepaper.pdf) and [python/tessera_id.py](../python/tessera_id.py)).
**Tickets:** TP-137 / TESS-00018.

TesseraID's variant `0x02` is a Hybrid Logical Clock in the Kulkarni et al. construction
(<https://cse.buffalo.edu/tech-reports/2014-04.pdf>) carried inside a portable 41-byte identifier. Several deployed
systems run HLCs of their own. This page maps fields, drift handling, and merge rules between TesseraID-HLC and four
of them, then walks a runnable example ingesting a CockroachDB timestamp into a TesseraID `observe()` call.

## Field correspondence

| System | Physical time | Logical counter | Node identity | Carried as |
|--------|---------------|-----------------|---------------|------------|
| **TesseraID-HLC** | 48-bit unsigned ms since Unix epoch (`TS`, bytes 0–5) | 16-bit (`CTR`, bytes 7–8) | none — 256-bit random tail instead | 41-byte portable wire format (variant `0x02`) |
| **CockroachDB HLC** (<https://www.cockroachlabs.com/docs/stable/architecture/transaction-layer>) | 64-bit signed ns (`WallTime int64`) | 32-bit (`Logical int32`) | none | internal struct; SQL surface `cluster_logical_timestamp()` returns `DECIMAL <wall_ns>.<logical, 10 digits>` (<https://www.cockroachlabs.com/docs/stable/functions-and-operators>) |
| **MongoDB cluster time** (<https://www.mongodb.com/docs/manual/reference/bson-types/>) | 32-bit s since epoch | 32-bit increment | HMAC `keyId` (cluster times are signed) | BSON `Timestamp` in `$clusterTime` |
| **uhlc-rs (Zenoh)** (<https://github.com/atolab/uhlc-rs>) | NTP64: 32-bit s + 32-bit fraction (~232 ps resolution) | none as a field — uniqueness via +1 on the NTP64 fraction's least-significant bits | up-to-16-byte `ID` appended to the time | `Timestamp = NTP64 ‖ ID` |
| **Dart `crdt` (cachapa)** (<https://github.com/cachapa/crdt>) | `DateTime` (ms-scale) | 16-bit (max `0xFFFF`) | `nodeId` string | text form `ISO8601-counterHex-nodeId` |

Reading the table: TesseraID and Dart `crdt` follow the HLC paper's recommended shape (ms physical time + 16-bit
counter). CockroachDB spends 96 bits for ns precision and a deep counter. MongoDB's 1-second physical resolution
leans almost entirely on its 32-bit increment. uhlc removes the counter as a field entirely by folding it into the
timestamp's low bits — elegant, but it means "time" creeps ahead of the wall clock under burst load.

## Drift handling — the comparison that matters

| System | Future-drift bound | On violation | Configurable? |
|--------|--------------------|--------------|----------------|
| **TesseraID-HLC** | `HLC_MAX_DRIFT_MS = 60_000` (peer > 60 s ahead of local physical time) | hard error (`HLCDriftError`), no output, never clamps | **No — fixed, normative, identical in all 8 languages** |
| CockroachDB | no per-observe rejection: the clock is forwarded; node-level enforcement instead — a node offset more than `--max-offset` (default 500 ms) from the cluster self-terminates; reads carry uncertainty intervals (<https://www.cockroachlabs.com/docs/stable/operational-faqs#what-happens-when-node-clocks-are-not-properly-synchronized>) | node crash / txn uncertainty restarts | yes (`--max-offset`) |
| MongoDB | `maxAcceptableLogicalClockDriftSecs` (default 31 536 000 s ≈ 1 year); cluster times beyond it are rejected, and HMAC signing prevents unauthorized advancement (<https://www.mongodb.com/docs/manual/reference/parameters/>) | rejects the cluster time | yes (server parameter) |
| uhlc-rs | `delta` (default **500 ms**; `UHLC_MAX_DELTA_MS` env var or `HLCBuilder::with_max_delta`) | `update_with_timestamp()` returns `Err` — caller should refuse the event (<https://docs.rs/uhlc/latest/uhlc/struct.HLC.html>) | yes |
| Dart `crdt` | `const _maxDrift = Duration(minutes: 1)` — same 60 s value as TesseraID | throws `ClockDriftException` | no (hard-coded library constant) |

Honest framing: TesseraID is **not** the only HLC that rejects drift — uhlc and Dart `crdt` do too, and Dart `crdt`
even picked the same 60 s constant. TesseraID's distinction is that the bound is a **fixed invariant of a portable
wire format**: 60 s, non-configurable, enforced byte-identically by eight independent implementations and pinned by
conformance vectors. In the other systems the bound is a tunable (or a library default) of one codebase.

Drift-bound translation when bridging: anything arriving from a CockroachDB- or uhlc-disciplined source (≤ 500 ms
skew) will never trip TesseraID's 60 s bound. Bridging from MongoDB's ~1-year tolerance can: handle `HLCDriftError`
at the boundary by quarantining or rejecting the message — never by clamping (that would defeat the monotonicity
guarantee; see [../CLAUDE.md](../CLAUDE.md)).

## Merge-rule comparison

All five descend from the same HLC merge — `l_new = max(l_old, l_msg, pt)` with counter rules per the Kulkarni
paper — but diverge at the edges:

- **TesseraID** implements the full three-way merge (see `HLCGenerator.new(observe=…)` in
  [python/tessera_id.py](../python/tessera_id.py)); counter overflow past `0xFFFF` bumps `l` by 1 ms and resets
  `c` to 0 — generation never fails for overflow.
- **CockroachDB** does the same forwarding merge with a 32-bit counter (overflow is practically unreachable).
- **MongoDB** advances to `max(local, received)` and increments on each tick of the 1-second window.
- **uhlc** computes `max(physical, last + 1 LSB, msg + 1 LSB)` — the merge and the counter are one operation on the
  NTP64 value.
- **Dart `crdt`** adopts the remote timestamp only when it is ahead (`merge`), and **throws** `OverflowException`
  when the 16-bit counter would exceed `0xFFFF` instead of bumping the timestamp — a real behavioral divergence from
  TesseraID under same-ms burst.

## Worked example: CockroachDB timestamp → TesseraID `observe()`

CockroachDB's `cluster_logical_timestamp()` returns a `DECIMAL` whose integer part is the HLC wall time in
nanoseconds and whose 10-digit fractional part is the logical counter
(<https://www.cockroachlabs.com/docs/stable/functions-and-operators>). To make a TesseraID-HLC causally dominate
that timestamp, build a synthetic 41-byte ID carrying the mapped `(l, c)` and pass it to `new_hlc(observe=…)` —
`observe()` only reads the timestamp (bytes 0–6) and counter (bytes 7–9) fields.

Lossiness to accept before using this (one-directional ingest only — do not round-trip):

- **ns → ms truncation.** TesseraID's 48-bit field is ms-scale; sub-ms ordering between CockroachDB events
  collapses. The snippet rounds the wall time **up** to the next ms so the observed value dominates every
  CockroachDB timestamp within the source millisecond.
- **32-bit → 16-bit counter.** Logical values above `0xFFFF` are unrepresentable; the snippet refuses them
  (in practice CockroachDB logical values are tiny).
- The 256-bit random tail has no CockroachDB counterpart; it is zeroed in the synthetic observe-ID (never emit a
  zero-tail ID — it exists only as `observe()` input).

Runnable snippet (from the repo root: `PYTHONPATH=tessera-id/python python3 crdb_observe.py`):

```python
#!/usr/bin/env python3
"""Map a CockroachDB cluster_logical_timestamp() value into a TesseraID-HLC observe() call."""
import tessera_id


def crdb_to_observe(crdb_ts: str) -> bytes:
    """Build a synthetic 41-byte TesseraID carrying CockroachDB HLC state.

    cluster_logical_timestamp() format: DECIMAL "<wall_ns>.<logical, 10 digits>".
    Only bytes 0-6 (timestamp) and 7-9 (counter) are read by observe(); the
    random tail is irrelevant here and left zeroed (never emit this value).
    """
    wall_ns_str, _, frac = crdb_ts.partition(".")
    logical = int(frac or "0")
    if logical > tessera_id.MAX_COUNTER:
        raise ValueError(
            f"CockroachDB logical {logical} exceeds TesseraID's 16-bit counter"
        )
    # Ceiling ns -> ms: the synthetic HLC value dominates every CockroachDB
    # timestamp inside the same source millisecond (sub-ms order is lost).
    l_msg_ms = -(-int(wall_ns_str) // 1_000_000)
    return (
        l_msg_ms.to_bytes(tessera_id.TIMESTAMP_BYTES, "big")
        + bytes([tessera_id.VARIANT_HLC])
        + logical.to_bytes(2, "big")
        + bytes(32)
    )


# A CockroachDB timestamp captured 2026-01-01T00:00:00.123456789Z, logical 42:
crdb_ts = "1767225600123456789.0000000042"

observed = crdb_to_observe(crdb_ts)
new_id = tessera_id.new_hlc(observe=observed)   # merge, then generate

obs_l = int.from_bytes(observed[0:6], "big")
obs_c = int.from_bytes(observed[7:9], "big")
new_l = int.from_bytes(new_id[0:6], "big")
new_c = int.from_bytes(new_id[7:9], "big")
assert (new_l, new_c) > (obs_l, obs_c), "HLC happened-before violated"
print(f"observed (l={obs_l}, c={obs_c}) -> generated (l={new_l}, c={new_c})")
print("new TesseraID-HLC:", tessera_id.encode_b64(new_id))
```

The assertion is the point: after `observe()`, the generated ID's `(l, c)` strictly dominates the mapped CockroachDB
state, so the TesseraID sorts after — and is causally ordered after — the CockroachDB event. If the mapped timestamp
were more than 60 s ahead of the local clock, `new_hlc` would raise `HLCDriftError` instead of producing an ID.

The reverse direction (TesseraID → CockroachDB/Mongo/uhlc/Dart) is intentionally out of scope: those systems own
their clocks, and injecting foreign HLC state into them is an operation their APIs do not expose. For positioning
context — why a portable HLC identifier at all — see [positioning.md](positioning.md).
