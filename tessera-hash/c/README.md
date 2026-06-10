# tessera-hash/c

C reference implementation of TesseraHash — the 73-byte SHAKE-256 content hash format (variant `0x03`).
The whitepaper at [../latex/](../latex/) is normative; the Python reference at
[../python/tessera_hash.py](../python/tessera_hash.py) is the readable canonical source.

SHAKE-256 comes from the shared vendored Keccak in [../../common/c/keccak.c](../../common/c/keccak.c) —
never re-vendored inside this project, per the umbrella supply-chain invariants. No other dependencies.

## Build / test

```bash
cd tessera-hash/c
make
make test
```

## Install / consumption

The library is **publish-ready but not distributed as a system package** — see the posture record at
[docs/decisions/2026-06-10-distribution-posture.md](../../docs/decisions/2026-06-10-distribution-posture.md).
Install from a checkout (TESS-00014):

```bash
cd tessera-hash/c
make install                          # PREFIX=/usr/local by default
make install PREFIX=/opt/tessera      # custom prefix
make install DESTDIR=/tmp/stage       # staged install (packaging)
```

This installs `tessera_hash.h` **and** `keccak.h` (needed by the header-only C++ wrapper) into
`$(PREFIX)/include/tessera/`, `libtessera_hash.a` (tessera_hash.o + keccak.o) into `$(PREFIX)/lib/`, and a
pkg-config file (generated from [tessera-hash.pc.in](tessera-hash.pc.in)) into `$(PREFIX)/lib/pkgconfig/`.
A downstream program then builds with (the `.pc` `Cflags` point inside `include/tessera/`, so include the
header flat — `#include <tessera_hash.h>`):

```bash
cc app.c $(pkg-config --cflags --libs tessera-hash)
```

Vendoring is equally supported: copy `tessera_hash.c`, `tessera_hash.h`, and
`../../common/c/keccak.{c,h}` into your tree (the Makefile shows the exact compile lines).
