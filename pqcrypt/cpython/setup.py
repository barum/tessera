"""Build script for the pqcrypt_ext CPython extension.

Run with:
    python3 setup.py build_ext --inplace
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
    name="pqcrypt_ext",
    sources=[
        "pqcrypt_ext.c",
        "../c/pqcrypt.c",
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
    name="pqcrypt_ext",
    version="1.0.0",
    description="CPython extension binding for the PQCrypt reference C implementation",
    ext_modules=[ext],
    python_requires=">=3.8",
)
