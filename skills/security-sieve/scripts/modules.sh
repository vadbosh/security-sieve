#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# modules.sh — Step 0 of security-sieve: count the source files of a
# repository and group them into modules of at most LIMIT files.
#
#   bash modules.sh <repo-dir> [<limit>]        limit defaults to 500
#
# Prints `files=<N>` first, then one line per module, largest first:
# `<count>  <directory>`. A group above the limit is split one directory
# deeper, and again, until none is above it. Files that sit directly in a
# directory being split are listed as `<directory> (files here)`.
#
# A rule in prose gave "src 3599" and "server 3473" as modules — one group
# holding the whole repository, which narrows nothing. Bash 3.2 compatible.

set -u
repo="${1:?usage: modules.sh <repo-dir> [<limit>]}"
limit="${2:-500}"
cd "$repo" || { echo "modules.sh: cannot enter $repo" >&2; exit 2; }

{ git ls-files 2>/dev/null || find . -type f -not -path '*/.git/*' | sed 's|^\./||'; } |
  grep -Ev '(^|/)(tests?|__tests__|spec|vendor|node_modules|dist|build|target|generated)/|\.min\.js$' |
  grep -E '\.(java|kt|scala|cs|py|js|jsx|ts|tsx|php|go|rb|rs|c|cc|cpp|swift|tf)$' |
  awk -v lim="$limit" '
    { p[++N] = $0 }
    function grp(pre,   i, rest, k, c) {
      for (i = 1; i <= N; i++) {
        if (pre != "" && index(p[i], pre) != 1) continue   # index(s, "") is 0 in busybox awk
        rest = substr(p[i], length(pre) + 1)
        k = index(rest, "/") ? substr(rest, 1, index(rest, "/")) : "."
        c[k]++
      }
      for (k in c) {
        if (k != "." && c[k] > lim) grp(pre k)
        else printf "%d\t%s\n", c[k], (k == "." ? (pre == "" ? "." : pre) " (files here)" : pre k)
      }
    }
    END {
      print "files=" N + 0
      if (N == 0) exit
      # the longest directory prefix all files share
      depth = split(p[1], a, "/") - 1
      for (i = 2; i <= N && depth > 0; i++) {
        m = split(p[i], b, "/") - 1; d = 0
        while (d < depth && d < m && a[d + 1] == b[d + 1]) d++
        depth = d
      }
      pre = ""; for (i = 1; i <= depth; i++) pre = pre a[i] "/"
      grp(pre)
    }' | { read -r first; echo "$first"; sort -rn; } > "${TMPDIR:-/tmp}/modules.$$"

# Above the limit the person decides the scope, and needs the measured cost
# to decide it. Printed here, not left to the model: two Codex runs out of
# three dropped it from the question and kept only the file count.
n="$(sed -n '1s/^files=//p' "${TMPDIR:-/tmp}/modules.$$")"
if [ "${n:-0}" -gt "$limit" ]; then
    cat <<EOF
say-to-user: $n source files. Measured on Claude Opus (2026-10-10): 144 C# files took
say-to-user: 8 minutes; 3888 Java files took 27 minutes and USD 42 in one pass, which looked
say-to-user: at about one file in nine, and 33 minutes and USD 57 in parts. Narrowing the
say-to-user: scope is cheaper and says what was covered.
EOF
fi
cat "${TMPDIR:-/tmp}/modules.$$"
rm -f "${TMPDIR:-/tmp}/modules.$$"
