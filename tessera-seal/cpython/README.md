# tessera-seal/cpython

CPython extension for TesseraSeal — mirrors the API of `../python/tessera_seal_fast.py` (not `../python/tessera_seal.py`).

**Status:** v2 placeholder. Lands once `tessera_seal_fast.py` is stable.

Authoritative spec: [../latex/](../latex/) and the built `../latex/TesseraSeal_Whitepaper.pdf`.

Follows the same convention as [`../../tessera-id/cpython/tessera_id_ext.c`](../../tessera-id/cpython/tessera_id_ext.c): direct C against the CPython API, no FFI bridges.
