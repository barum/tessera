# tessera-hash/cpp

C++ reference implementation of TesseraHash — the 73-byte SHAKE-256 content hash format (variant `0x03`),
as a header-only wrapper ([tessera_hash.hpp](tessera_hash.hpp), C++20) over the shared C Keccak from
[../../common/c/](../../common/c/). The whitepaper at [../latex/](../latex/) is normative.

Unlike the fully self-contained TesseraID C++ header, this header has **one link dependency**: a Keccak
object (`keccak.o`, or any of the static libs below).

## Build / test

```bash
cd tessera-hash/cpp
make test
```

## Install / consumption

The library is **publish-ready but not distributed as a system package** — see the posture record at
[docs/decisions/2026-06-10-distribution-posture.md](../../docs/decisions/2026-06-10-distribution-posture.md).
Install from a checkout (TESS-00014):

```bash
# Headers: this Makefile installs the .hpp; the sibling C Makefile installs
# tessera_hash.h + keccak.h + libtessera_hash.a + the pkg-config file.
cd tessera-hash/c   && make install            # C header + static lib + .pc
cd ../cpp           && make install            # → $(PREFIX)/include/tessera/tessera_hash.hpp
```

Then compile and link against the installed prefix:

```bash
c++ -std=c++20 app.cpp $(pkg-config --cflags --libs tessera-hash)
```

(`libtessera_hash.a` bundles the Keccak object; `libtessera_common.a` from
[../../common/c/](../../common/c/) works too.) Vendoring is equally supported: copy `tessera_hash.hpp`
plus `../../common/c/keccak.{c,h}` into your tree and compile `keccak.c` as C11.
