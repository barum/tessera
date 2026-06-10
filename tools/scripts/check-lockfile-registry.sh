#!/usr/bin/env bash
set -euo pipefail

# check-lockfile-registry.sh — CI guard (TP-008).
#
# Every "resolved" URL in every committed package-lock.json must point at the
# public npm registry (https://registry.npmjs.org/). Private/corporate registry
# URLs (e.g. an internal Artifactory) break `npm ci` for public consumers and
# leak internal hostnames. Local path links (`file:` deps, written by npm as
# relative-path "resolved" values) are allowed.
#
# Usage: tools/scripts/check-lockfile-registry.sh [repo-root]
#   repo-root defaults to the repository containing this script.
#
# Exit codes: 0 = clean, 1 = offending resolved URLs found (printed to stderr).

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
allowed='https://registry.npmjs.org/'
status=0

while IFS= read -r lockfile; do
  offenders="$(grep -nE '"resolved"[[:space:]]*:[[:space:]]*"https?://' "$lockfile" \
    | grep -vE '"resolved"[[:space:]]*:[[:space:]]*"https://registry\.npmjs\.org/' || true)"
  if [[ -n "$offenders" ]]; then
    status=1
    printf 'ERROR: %s contains resolved URLs outside %s:\n%s\n' \
      "$lockfile" "$allowed" "$offenders" >&2
  fi
done < <(find "$root" -name package-lock.json -not -path '*/node_modules/*')

if [[ "$status" -eq 0 ]]; then
  echo "OK: all package-lock.json 'resolved' URLs point at ${allowed}"
else
  echo "FAIL: private-registry URLs found in lockfile(s); regenerate against ${allowed}" >&2
fi
exit "$status"
