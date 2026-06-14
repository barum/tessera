#!/usr/bin/env bash
# sync-mirrors.sh — generate a per-language publish-ready mirror from this hub.
#
# Usage:  tools/mirror/sync-mirrors.sh <lang> [<ref>] [<outdir>]
#   <lang>   one of: rust python typescript go c cpp java cpython
#   <ref>    hub git ref to generate from (default: HEAD)
#   <outdir> where to write the mirror tree (default: ../tessera-<lang>)
#
# It stages only git-tracked files from <ref> (clean by construction — no build artifacts,
# none of the dead-blob history), applies the per-language identifier/path rewrites, wires the
# tessera-vectors submodule, writes provenance (SOURCE) + SPEC.md, and prints next steps. It does
# NOT push or create repos (do that explicitly) and does NOT modify the hub. See
# docs/decisions/2026-06-13-hub-and-mirrors.md for the full recipe and rationale.
set -euo pipefail
shopt -s nullglob

HUB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANG_="${1:?usage: sync-mirrors.sh <lang> [ref] [outdir]}"
REF="${2:-HEAD}"
OUT="${3:-$HUB/../tessera-$LANG_}"
HUBSHA="$(git -C "$HUB" rev-parse "$REF")"
VECTORS_REPO="git@github.com:barum/tessera-vectors.git"
VECTORS_TAG="v1.3.1"

stage() {  # stage <hub-subpath> <dest> <strip>
  mkdir -p "$2"; git -C "$HUB" archive "$REF" "$1" | tar -x -C "$2" --strip-components="$3"
}
add_vectors() { ( cd "$OUT" && git init -q -b main 2>/dev/null || true
  git submodule add -q "$VECTORS_REPO" _vectors 2>/dev/null || true
  cd _vectors && git checkout -q "$VECTORS_TAG" ); }
write_source() { cat > "$OUT/SOURCE" <<EOF
hub_repo=github.com/barum/tessera
hub_sha=$HUBSHA
generated=$LANG_ mirror
vectors=tessera-vectors @ $VECTORS_TAG (git submodule _vectors)
EOF
}

echo ">> generating tessera-$LANG_ from hub $HUBSHA into $OUT"
rm -rf "$OUT"; mkdir -p "$OUT"

case "$LANG_" in
  rust)
    for p in id hash seal; do stage "tessera-$p/rust" "$OUT/tessera-$p" 2; rm -rf "$OUT/tessera-$p/fuzz"
      perl -pi -e 's{github\.com/barum/tessera"}{github.com/barum/tessera-rust"}' "$OUT/tessera-$p/Cargo.toml"; done
    stage tools/conformance/rust "$OUT/conformance" 3; rm -rf "$OUT/conformance/target" "$OUT/conformance/Cargo.lock"
    perl -pi -e 's{\.\./\.\./\.\./tessera-(id|hash|seal)/rust}{../tessera-$1}g' "$OUT/conformance/Cargo.toml"
    perl -pi -e 's{const KAT_DIR: &str = "\.\./conformance/vectors";}{const KAT_DIR: \&str = "../_vectors/vectors/tessera-seal";}' "$OUT/tessera-seal/tests/integration.rs"
    printf '[workspace]\nresolver = "3"\nmembers = ["tessera-id","tessera-hash","tessera-seal","conformance"]\n\n[profile.release]\nopt-level = 3\nlto = true\ncodegen-units = 1\n' > "$OUT/Cargo.toml" ;;
  python)
    for p in id hash seal; do stage "tessera-$p/python" "$OUT/tessera-$p" 2
      rm -rf "$OUT/tessera-$p/__pycache__" "$OUT/tessera-$p"/*.egg-info "$OUT/tessera-$p/fuzz"
      perl -pi -e 's{github.com/barum/tessera"}{github.com/barum/tessera-python"}g' "$OUT/tessera-$p/pyproject.toml" 2>/dev/null || true; done
    stage tools/conformance/python/python_runner.py "$OUT/conformance" 3
    perl -0pi -e 's{REPO_ROOT = HERE\.parent\.parent\.parent.*}{REPO_ROOT = HERE.parent}' "$OUT/conformance/python_runner.py"
    perl -pi -e 's{REPO_ROOT / "tessera-(id|hash|seal)" / "python"}{REPO_ROOT / "tessera-$1"}g' "$OUT/conformance/python_runner.py"
    perl -pi -e 's{"\.\.", "conformance", "vectors",}{"..", "_vectors", "vectors", "tessera-seal",}g' "$OUT/tessera-seal/test_tessera_seal.py" ;;
  typescript)
    for p in id hash seal; do stage "tessera-$p/typescript" "$OUT/tessera-$p" 2
      rm -rf "$OUT/tessera-$p/node_modules" "$OUT/tessera-$p/dist" "$OUT/tessera-$p/fuzz"
      perl -pi -e 's{github\.com/barum/tessera(\.git)?}{github.com/barum/tessera-typescript}g; s{"directory": "tessera-\w+/typescript"}{"directory": "tessera-$1"}g' "$OUT/tessera-$p/package.json" 2>/dev/null || true; done
    stage tools/conformance/typescript "$OUT/conformance" 3; rm -rf "$OUT/conformance/node_modules" "$OUT/conformance/dist"
    perl -pi -e 's{file:\.\./\.\./\.\./tessera-(id|hash)/typescript}{file:../tessera-$1}g' "$OUT/conformance/package.json"
    perl -pi -e 's{const KAT_DIR = "\.\./conformance/vectors";}{const KAT_DIR = "../_vectors/vectors/tessera-seal";}' "$OUT/tessera-seal/test_tessera_seal.ts" ;;
  go)
    for p in id hash seal; do stage "tessera-$p/go" "$OUT/tessera-$p" 2; rm -rf "$OUT/tessera-$p/testdata/fuzz"; done
    stage tools/conformance/go "$OUT/conformance" 3
    find "$OUT" -type f \( -name '*.go' -o -name 'go.mod' \) -print0 | while IFS= read -r -d '' f; do
      perl -pi -e 's{github\.com/barum/tessera/tessera-(id|hash|seal)/go}{github.com/barum/tessera-go/tessera-$1}g' "$f"; done
    for g in "$OUT/conformance/go.mod" "$OUT/conformance/tessera_seal_runner/go.mod"; do [ -f "$g" ] && perl -0pi -e 's{^replace\s*\([^)]*\)\n}{}mg; s{^replace .*=>.*\n}{}mg' "$g"; done
    printf '\nreplace github.com/barum/tessera-go/tessera-id => ../tessera-id\n' >> "$OUT/tessera-hash/go.mod"
    printf '\nreplace (\n\tgithub.com/barum/tessera-go/tessera-id => ../tessera-id\n\tgithub.com/barum/tessera-go/tessera-hash => ../tessera-hash\n)\n' >> "$OUT/conformance/go.mod"
    printf '\nreplace github.com/barum/tessera-go/tessera-seal => ../../tessera-seal\n' >> "$OUT/conformance/tessera_seal_runner/go.mod" ;;
  c|cpp)
    stage common/c "$OUT/_vendor" 0
    for p in id hash seal; do stage "tessera-$p/c" "$OUT/tessera-$p" 1
      [ "$LANG_" = cpp ] && stage "tessera-$p/cpp" "$OUT/tessera-$p" 1
      for mk in "$OUT/tessera-$p/c/Makefile" "$OUT/tessera-$p/cpp/Makefile"; do [ -f "$mk" ] && perl -pi -e 's{\.\./\.\./common/c}{../../_vendor/common/c}g' "$mk"; done; done
    perl -pi -e 's{#include "\.\./\.\./common/c/random\.h"}{#include "random.h"}' "$OUT/tessera-id/c/tessera_id.c"
    perl -pi -e 's{\.\./conformance/vectors}{../../_vectors/vectors/tessera-seal}g' "$OUT/tessera-seal/${LANG_}/test_tessera_seal.${LANG_/cpp/cpp}" 2>/dev/null || true
    perl -pi -e 's{\.\./conformance/vectors}{../../_vectors/vectors/tessera-seal}g' "$OUT/tessera-seal/c/test_tessera_seal.c" 2>/dev/null || true
    stage "tools/conformance/$LANG_" "$OUT/conformance" 3
    [ -f "$OUT/conformance/Makefile" ] && perl -pi -e 's{^(REPO_ROOT\s*:=\s*)\.\./\.\./\.\.\s*$}{${1}..\n}; s{\$\(REPO_ROOT\)/common/c}{\$(REPO_ROOT)/_vendor/common/c}g; s{\.\./\.\./\.\./tessera-(id|hash)/cpp}{../tessera-$1/cpp}g' "$OUT/conformance/Makefile"
    ( cd "$OUT/_vendor/common/c" && { echo "hub_sha=$HUBSHA"; for f in *.c *.h; do printf '%s  %s\n' "$(shasum -a256 "$f"|cut -d' ' -f1)" "$f"; done; } > "$OUT/_vendor/VENDOR.lock" ) ;;
  java)
    for p in id hash seal; do stage "tessera-$p/java" "$OUT/tessera-$p" 1
      perl -pi -e 's{<groupId>com\.tessera</groupId>}{<groupId>io.github.barum</groupId>}g' "$OUT/tessera-$p/java/pom.xml"; done
    mkdir -p "$OUT/tessera-hash/java/src/main/java/com/tessera/common"
    cp "$HUB/common/java/com/tessera/common/Keccak.java" "$OUT/tessera-hash/java/src/main/java/com/tessera/common/Keccak.java"
    perl -0pi -e 's{\n  <build>\s*\n(?:.*\n)*?  </build>\n}{\n}' "$OUT/tessera-hash/java/pom.xml"
    perl -pi -e 's{\.\./conformance/vectors}{../../_vectors/vectors/tessera-seal}g' "$OUT/tessera-seal/java/src/test/java/com/tessera/seal/TesseraSealTest.java" 2>/dev/null || true ;;
  cpython)
    mkdir -p "$OUT/tessera-id-ext/vendor" "$OUT/tessera-seal-ext/vendor"
    stage tessera-id/cpython "$OUT/tessera-id-ext" 2; rm -rf "$OUT/tessera-id-ext"/{build,fuzz,common,tessera-hash,__pycache__}
    cp "$HUB"/tessera-id/c/tessera_id.{c,h} "$HUB"/tessera-hash/c/tessera_hash.{c,h} "$HUB"/common/c/{keccak,random}.{c,h} "$HUB"/common/c/tessera_header.h "$OUT/tessera-id-ext/vendor/"
    perl -pi -e 's{#include "\.\./\.\./common/c/random\.h"}{#include "random.h"}' "$OUT/tessera-id-ext/vendor/tessera_id.c"
    perl -pi -e 's{"\.\./c/(\w+\.c)"}{"vendor/$1"}g; s{"\.\./\.\./tessera-hash/c/(\w+\.c)"}{"vendor/$1"}g; s{"\.\./\.\./common/c/(\w+\.c)"}{"vendor/$1"}g; s{include_dirs=\[[^\]]*\]}{include_dirs=["vendor"]}' "$OUT/tessera-id-ext/setup.py"
    stage tessera-seal/cpython "$OUT/tessera-seal-ext" 2; rm -rf "$OUT/tessera-seal-ext"/{build,common,__pycache__}
    cp "$HUB"/tessera-seal/c/tessera_seal.{c,h} "$HUB"/common/c/hkdf_sha3.{c,h} "$HUB"/common/c/tessera_header.h "$OUT/tessera-seal-ext/vendor/"
    perl -pi -e 's{"\.\./c/(\w+\.c)"}{"vendor/$1"}g; s{"\.\./\.\./common/c/(\w+\.c)"}{"vendor/$1"}g; s{"\.\./c"}{"vendor"}g; s{"\.\./\.\./common/c"}{"vendor"}g' "$OUT/tessera-seal-ext/setup.py"
    perl -pi -e 's{HERE\.parent / "conformance" / "vectors"}{HERE.parent / "_vectors" / "vectors" / "tessera-seal"}' "$OUT/tessera-seal-ext/test_tessera_seal_ext.py" ;;
  *) echo "unknown lang: $LANG_"; exit 2 ;;
esac

add_vectors
write_source
echo ">> done. Hygiene files (LICENSE/NOTICE/SPEC.md/README/CI/release) are added per the template"
echo "   in docs/decisions/2026-06-13-hub-and-mirrors.md. Verify with the mirror's conformance/replay.sh,"
echo "   then: git add -A && commit (trailer: Tessera-Hub-SHA: $HUBSHA) && push to barum/tessera-$LANG_."
