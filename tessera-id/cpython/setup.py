"""Build script for the tessera_id_ext CPython extension.

Run with:
    python3 setup.py build_ext --inplace

Project metadata (name/version/license) lives in pyproject.toml (TESS-00014);
this file keeps only the Extension definition. Build-from-checkout only — the
sources below reach outside this directory, so sdists/wheels built from this
directory alone would be broken (see pyproject.toml).
"""
from setuptools import Extension, setup

ext = Extension(
    name="tessera_id_ext",
    # The current tessera_id_ext exposes BOTH TesseraID and TesseraHash
    # bindings from a single extension. Splitting into two extensions
    # (tessera_id_ext + tessera_hash_ext) is a tracked follow-up; for now we
    # pull sources from all three C trees.
    sources=[
        "tessera_id_ext.c",
        "../c/tessera_id.c",
        "../../tessera-hash/c/tessera_hash.c",
        "../../common/c/keccak.c",
        # tessera_id.c calls tessera_csprng(), defined here. Omitting this
        # source builds a .so with an unresolved '_tessera_csprng' symbol that
        # fails at import (dlopen) on flat-namespace platforms.
        # (cf. tessera-id/c/Makefile.)
        "../../common/c/random.c",
    ],
    include_dirs=["../c", "../../tessera-hash/c", "../../common/c"],
    extra_compile_args=[
        "-O3",
        "-Wall",
        "-Wextra",
        "-std=c11",
        "-D_POSIX_C_SOURCE=200809L",
        "-D_DEFAULT_SOURCE",
        "-DNDEBUG",
    ],
)

setup(
    ext_modules=[ext],
)
