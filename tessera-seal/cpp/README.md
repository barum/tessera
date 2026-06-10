# tessera-seal/cpp

C++ reference implementation of TesseraSeal v1.

**Status:** v1.1 placeholder. Wraps the C library at [`../c/`](../c/).

Authoritative spec: [../latex/](../latex/) and the built `../latex/TesseraSeal_Whitepaper.pdf`.

## Build / test

```bash
cd tessera-seal/cpp
make test     # builds the C reference first, then the C++ tests
```

## Install / consumption

The library is **publish-ready but not distributed as a system package** — see the posture record at
[docs/decisions/2026-06-10-distribution-posture.md](../../docs/decisions/2026-06-10-distribution-posture.md).
Install from a checkout (TESS-00014):

```bash
cd tessera-seal/c   && make install   # C header + libtessera_seal.a + pkg-config file
cd ../cpp           && make install   # → $(PREFIX)/include/tessera/tessera_seal.hpp
```

Then compile and link against the installed prefix (OpenSSL 3.5+ required, per the C reference):

```bash
c++ -std=c++20 app.cpp $(pkg-config --cflags --libs tessera-seal) -lcrypto
```
