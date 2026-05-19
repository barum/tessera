"""Build script for the pqid_ext CPython extension.

Run with:
    python3 setup.py build_ext --inplace
"""
from setuptools import Extension, setup

ext = Extension(
    name="pqid_ext",
    sources=["pqid_ext.c", "../c/pqid.c"],
    include_dirs=["../c"],
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
