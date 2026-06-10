# tessera-id/c

C reference implementation of TesseraID — the 41-byte sortable identifier (Standard `0x01` + HLC `0x02`
variants). Per the authority order in [../CLAUDE.md](../CLAUDE.md), [tessera_id.h](tessera_id.h) pins the
**canonical ABI** (field offsets, error codes, function signatures); the Python reference at
[../python/tessera_id.py](../python/tessera_id.py) is the readable canonical source for semantics.

Randomness comes from the shared OS-CSPRNG wrapper in [../../common/c/random.c](../../common/c/random.c)
(`getrandom`/`getentropy`/`BCryptGenRandom`/`/dev/urandom` — no userspace PRNG fallback, per the umbrella
security invariants). No other dependencies.

## Build / test / bench

```bash
cd tessera-id/c
make          # builds test + bench binaries
make test
make bench
```

## Install / consumption

The library is **publish-ready but not distributed as a system package** — see the posture record at
[docs/decisions/2026-06-10-distribution-posture.md](../../docs/decisions/2026-06-10-distribution-posture.md).
Install from a checkout (TESS-00014):

```bash
cd tessera-id/c
make install                          # PREFIX=/usr/local by default
make install PREFIX=/opt/tessera      # custom prefix
make install DESTDIR=/tmp/stage       # staged install (packaging)
```

This installs `tessera_id.h` into `$(PREFIX)/include/tessera/`, `libtessera_id.a` into `$(PREFIX)/lib/`,
and a pkg-config file (generated from [tessera-id.pc.in](tessera-id.pc.in)) into `$(PREFIX)/lib/pkgconfig/`.
A downstream program then builds with (the `.pc` `Cflags` point inside `include/tessera/`, so include the
header flat — `#include <tessera_id.h>`):

```bash
cc app.c $(pkg-config --cflags --libs tessera-id)
```

Vendoring is equally supported: copy `tessera_id.c`, `tessera_id.h`, and `../../common/c/random.{c,h}` into
your tree (the Makefile shows the exact compile lines).
