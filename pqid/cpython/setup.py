"""Build script for the pqid_ext CPython extension.

Run with:
    python3 setup.py build_ext --inplace
"""
from setuptools import Extension, setup

ext = Extension(
    name="pqid_ext",
    # The current pqid_ext exposes BOTH PQID and PQHash bindings from a single
    # extension. Splitting into two extensions (pqid_ext + pqhash_ext) is a
    # tracked follow-up; for now we pull sources from all three C trees.
    sources=[
        "pqid_ext.c",
        "../c/pqid.c",
        "../../pqhash/c/pqhash.c",
        "../../common/c/keccak.c",
    ],
    include_dirs=["../c", "../../pqhash/c", "../../common/c"],
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
    name="pqid_ext",
    version="1.0.0",
    description="CPython extension binding for the PQID reference C implementation",
    ext_modules=[ext],
    python_requires=">=3.8",
)
