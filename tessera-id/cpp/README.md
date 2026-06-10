# tessera-id/cpp

C++ reference implementation of TesseraID — the 41-byte sortable identifier (Standard `0x01` + HLC `0x02`
variants), as a **fully self-contained header-only library** ([tessera_id.hpp](tessera_id.hpp), C++20, no
link dependency). The whitepaper at [../latex/](../latex/) is normative; the C header at
[../c/tessera_id.h](../c/tessera_id.h) pins the canonical ABI this header mirrors.

## Build / test / bench

```bash
cd tessera-id/cpp
make test
make bench
```

## Install / consumption

The library is **publish-ready but not distributed as a system package** — see the posture record at
[docs/decisions/2026-06-10-distribution-posture.md](../../docs/decisions/2026-06-10-distribution-posture.md).
Two equally supported paths (TESS-00014):

```bash
# 1. Install the header system-wide (or staged)
cd tessera-id/cpp
make install                          # → $(PREFIX)/include/tessera/tessera_id.hpp
make install PREFIX=/opt/tessera
make install DESTDIR=/tmp/stage

# 2. Vendor: copy the single header into your tree
cp tessera_id.hpp <your-project>/third_party/tessera/
```

Then compile with `-I$(PREFIX)/include` (or your vendored path) and `#include <tessera/tessera_id.hpp>` —
no library to link.
