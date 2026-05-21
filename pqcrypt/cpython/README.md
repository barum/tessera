# pqcrypt/cpython

CPython extension for PQCrypt — mirrors the API of `../python/pqcrypt_fast.py` (not `../python/pqcrypt.py`).

**Status:** v2 placeholder. Lands once `pqcrypt_fast.py` is stable.

Authoritative spec: [../latex/](../latex/) and the built `../latex/PQCrypt_Whitepaper.pdf`.

Follows the same convention as [`../../pqid/cpython/pqid_ext.c`](../../pqid/cpython/pqid_ext.c): direct C against the CPython API, no FFI bridges.
