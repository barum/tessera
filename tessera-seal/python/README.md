# tessera-seal/python

Python reference implementation of TesseraSeal v1. **Readable canonical source** per the authority order in `../CLAUDE.md`.

## Status

- Implementation: complete (PQCK-00003).
- Tests: 56/56 pass.
- Conformance vectors: deterministic, generated from this reference (see `../conformance/`).

## Install

```bash
cd tessera-seal/python
pip install -r requirements.txt
```

Dependencies:

- `cryptography ≥ 46` — AES-256-GCM and ChaCha20-Poly1305.
- `kyber-py ≥ 1.0` — ML-KEM-1024 (renamed to `MLKem1024` at the binding boundary; no "Kyber" name leaks into tessera_seal's public surface).
- `pycryptodome ≥ 3.20` — only required by the conformance-vector generator's deterministic DRBG mode. Production callers can omit it.

## Test

```bash
python3 -m pytest test_tessera_seal.py -v
```

Pinned coverage classes: constants, round-trip per suite, envelope structure, variant-byte rejection (10 cases), suite-byte rejection (7 cases), AD binding (positive + negative), tamper detection (every header byte + body sections), length limits, determinism, peek-header + min-timestamp helpers, sender context, cross-suite interop, key-wrapper validation.

## Bench

```bash
python3 bench.py
```

Reference numbers under `../benchmarks/python.txt`. Note: kyber-py is pure-Python; the C/Go/Rust ports will be roughly 100× faster on the ML-KEM operations.

## Files

| File | Purpose |
|------|---------|
| `tessera_seal.py` | Readable canonical reference |
| `test_tessera_seal.py` | 56-test suite |
| `bench.py` | Micro-bench |
| `requirements.txt` | Pinned dependency floor |

A `tessera_seal_fast.py` optimized variant is planned for v1.1 alongside the CPython extension; see the project CLAUDE.md.

## Authority

Whitepaper at `../latex/TesseraSeal_Whitepaper.pdf` is normative. This file follows the whitepaper. The C reference (`../c/`) pins the ABI. Other languages port byte-identical to this Python reference.
