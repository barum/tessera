"""Build script for the tessera_seal_ext CPython extension.

Run with:
    python3 setup.py build_ext --inplace

Project metadata (name/version/license) lives in pyproject.toml (TESS-00014);
this file keeps only the Extension definition + OpenSSL discovery. Build-from-
checkout only — the sources below reach outside this directory, so sdists/
wheels built from this directory alone would be broken (see pyproject.toml).
"""
import os
import sys
from setuptools import Extension, setup

# OpenSSL discovery (Homebrew default on macOS, libssl-dev on Linux).
openssl_include = os.environ.get("OPENSSL_INCLUDE", "")
openssl_lib = os.environ.get("OPENSSL_LIB", "")
if not openssl_include:
    for candidate in (
        "/opt/homebrew/opt/openssl@3/include",
        "/usr/local/opt/openssl@3/include",
        "/usr/include",
    ):
        if os.path.exists(os.path.join(candidate, "openssl/evp.h")):
            openssl_include = candidate
            break
if not openssl_lib:
    for candidate in (
        "/opt/homebrew/opt/openssl@3/lib",
        "/usr/local/opt/openssl@3/lib",
        "/usr/lib",
    ):
        if os.path.exists(os.path.join(candidate, "libcrypto.dylib")) or \
           os.path.exists(os.path.join(candidate, "libcrypto.so")):
            openssl_lib = candidate
            break

include_dirs = ["../c", "../../common/c"]
if openssl_include:
    include_dirs.append(openssl_include)

library_dirs = []
if openssl_lib:
    library_dirs.append(openssl_lib)

ext = Extension(
    name="tessera_seal_ext",
    sources=[
        "tessera_seal_ext.c",
        "../c/tessera_seal.c",
        "../../common/c/hkdf_sha3.c",
    ],
    include_dirs=include_dirs,
    library_dirs=library_dirs,
    libraries=["crypto"],
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
