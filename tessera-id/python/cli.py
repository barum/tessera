#!/usr/bin/env python3
"""From-checkout launcher for the TesseraID CLI.

The implementation lives in tessera_id_cli.py, which pyproject.toml installs
as a flat module and exposes as the `tessera-id` console command. This shim
keeps the documented from-checkout form working without an install:

    python3 tessera-id/python/cli.py <subcommand> ...

It is deliberately NOT installed: the three sibling projects (tessera-id,
tessera-hash, tessera-seal) each ship a cli.py, so the installed module name
must be unique per project (here: tessera_id_cli) to allow all three
distributions to coexist in one environment.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tessera_id_cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
