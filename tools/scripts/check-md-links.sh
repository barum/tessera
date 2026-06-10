#!/usr/bin/env bash
# check-md-links.sh — verify every relative markdown link in the repo resolves.
#
# Scans all *.md files (excluding build/dependency dirs), extracts inline
# [text](target) and reference-style [label]: target links, and checks that
# every relative target exists on disk. Absolute URLs (http/https/mailto),
# pure-anchor links (#section), and angle-bracket autolinks are skipped;
# #fragments and ?queries are stripped before resolution.
#
# Usage:
#   bash tools/scripts/check-md-links.sh            # check repo at script's root
#   bash tools/scripts/check-md-links.sh <dir>      # check another tree
#
# Exit status: 0 = all relative links resolve; 1 = at least one broken link
# (each printed as "<file>:<line>: broken link -> <target>").
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

python3 - "$ROOT" <<'PYEOF'
import os
import re
import sys
import urllib.parse

root = os.path.abspath(sys.argv[1])

EXCLUDE_DIRS = {
    ".git", "node_modules", "target", "__pycache__", ".venv", "venv",
    "build", "dist", ".vscode", ".idea",
}

# Inline links: [text](target "title") — tolerate one level of nested parens
INLINE_RE = re.compile(r"\[[^\]]*\]\(\s*(<[^>]*>|[^()\s]+(?:\([^()]*\)[^()\s]*)*)")
# Reference definitions: [label]: target
REF_RE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s+(\S+)")

SKIP_SCHEMES = ("http://", "https://", "mailto:", "ftp://", "tel:")

def md_files():
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for f in filenames:
            if f.endswith(".md"):
                yield os.path.join(dirpath, f)

def strip_target(t):
    t = t.strip()
    if t.startswith("<") and t.endswith(">"):
        t = t[1:-1]
    # drop trailing markdown punctuation that regex may have captured
    t = t.rstrip(").,;")
    # split off title: [x](path "title") — title handled by \S+ already
    t = t.split("#", 1)[0]
    t = t.split("?", 1)[0]
    return urllib.parse.unquote(t)

def in_code_fence_map(lines):
    fenced, fences = [], False
    for ln in lines:
        if ln.lstrip().startswith(("```", "~~~")):
            fences = not fences
            fenced.append(True)
            continue
        fenced.append(fences)
    return fenced

broken = 0
checked = 0
for path in sorted(md_files()):
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    fenced = in_code_fence_map(lines)
    for lineno, line in enumerate(lines, 1):
        if fenced[lineno - 1]:
            continue
        # strip inline code spans so `[x](y)` examples don't count
        scrubbed = re.sub(r"`[^`]*`", "", line)
        targets = [m for m in INLINE_RE.findall(scrubbed)]
        ref = REF_RE.match(scrubbed)
        if ref:
            targets.append(ref.group(1))
        for raw in targets:
            t = raw.strip()
            if t.lower().startswith(SKIP_SCHEMES) or t.startswith("#") or not t:
                continue
            if t.startswith("<") and (t[1:].lower().startswith(SKIP_SCHEMES)):
                continue
            target = strip_target(t)
            if not target:
                continue  # pure anchor/query link
            if target.startswith("/"):
                resolved = os.path.join(root, target.lstrip("/"))
            else:
                resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
            checked += 1
            if not os.path.exists(resolved):
                broken += 1
                rel = os.path.relpath(path, root)
                print(f"{rel}:{lineno}: broken link -> {raw.strip()}")

print(f"check-md-links: {checked} relative links checked, {broken} broken", file=sys.stderr)
sys.exit(1 if broken else 0)
PYEOF
