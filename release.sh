#!/usr/bin/env bash
# Release checks for the security-sieve skill.
#
#   ./release.sh check      version ↔ changelog ↔ tag ↔ HEAD ↔ installed copies,
#                           plus the skill's own integrity (index, licenses,
#                           upstream copies, machine paths)
#   ./release.sh tag        create the tag for the current version
#   ./release.sh upstream   has getsentry/skills changed since the pinned
#                           commit? Needs network and `gh`; not part of check
#
# The version lives in two places: `version:` in SKILL.md and the newest
# `## X.Y.Z — date` section of CHANGELOG.md. The tag is the third.
set -uo pipefail

tilde() { case "$1" in "$HOME"*) printf '~%s' "${1#"$HOME"}" ;; *) printf '%s' "$1" ;; esac; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME=security-sieve
SKILL_DIR="$SRC/skills/$NAME"
SKILL="$SKILL_DIR/SKILL.md"
LOG="$SRC/CHANGELOG.md"
UPSTREAM="$SRC/UPSTREAM"
COPIES=0

# Paths that belong to this machine — a mirror this repository does not own.
# Untracked on purpose: a clone has its own answer or none.
# shellcheck disable=SC1091
[ -f "$SRC/.release.local" ] && . "$SRC/.release.local"

version() { grep -m1 '^version:' "$SKILL" | sed 's/version: *"//; s/"//'; }

shipped() {
    (cd "$SKILL_DIR" && find . -type f ! -name '*.bak.*' | sed 's|^\./||' | sort)
}

installed_dirs() {
    local d
    for d in "$HOME/.claude/skills/$NAME" \
             "$HOME/.config/opencode/skills/$NAME" \
             "$HOME/.codex/skills/$NAME" \
             ${SECURITY_SIEVE_MIRRORS:-}; do
        [ -f "$d/SKILL.md" ] && printf '%s\n' "$d"
    done
}

copies() {
    local v="$1" d behind=0 n=0 iv same f
    while read -r d; do
        [ -n "$d" ] || continue
        n=$((n + 1))
        iv="$(grep -m1 '^version:' "$d/SKILL.md" | sed 's/version: *"//; s/"//')"
        same=1
        while read -r f; do
            cmp -s "$SKILL_DIR/$f" "$d/$f" || same=0
        done < <(shipped)
        [ "$iv" = "$v" ] && [ "$same" -eq 1 ] && continue
        [ "$behind" -eq 0 ] && echo "  installed copies behind the source:"
        behind=$((behind + 1))
        echo "    $(tilde "$d")  version $iv$([ "$same" -eq 0 ] && echo ", content differs")"
    done < <(installed_dirs)

    if [ "$behind" -gt 0 ]; then
        echo "                    ./install.sh refreshes the assistant directories"
        return 1
    fi
    if [ "$n" -eq 0 ]; then
        echo "  installed copies:  none on this machine — nothing to compare"
        return 0
    fi
    COPIES=$n
    echo "  installed copies:  $n, all at $v"
}

# Every guide SKILL.md names must exist, and every guide shipped must be named:
# an index row for a missing file sends the reviewer nowhere, and a file no row
# names is never loaded. Seven such rows sat in the upstream index for months.
index() {
    local named missing unnamed
    named="$(grep -o '`[a-z-]*\.md`' "$SKILL" | tr -d '`' | sort -u)"
    missing="$(echo "$named" | while read -r f; do
        [ -n "$f" ] || continue
        [ -f "$SKILL_DIR/references/$f" ] || [ -f "$SKILL_DIR/languages/$f" ] \
            || [ -f "$SKILL_DIR/infrastructure/$f" ] || echo "$f"
    done | sort -u)"
    unnamed="$(shipped | grep -E '^(references|languages|infrastructure)/' | while read -r f; do
        echo "$named" | grep -qx "$(basename "$f")" || echo "$f"
    done)"
    if [ -n "$missing$unnamed" ]; then
        [ -n "$missing" ] && { echo "  index:            named in SKILL.md, no such file:"; echo "$missing" | sed 's/^/    /'; }
        [ -n "$unnamed" ] && { echo "  index:            shipped, never named in SKILL.md:"; echo "$unnamed" | sed 's/^/    /'; }
        return 1
    fi
    echo "  index:            $(echo "$named" | grep -c .) guides named, all present, none unnamed"
}

# A guide is either a verbatim upstream copy (CC BY-SA 4.0, listed in
# UPSTREAM) or our own (Apache-2.0, SPDX line first). Anything else has no
# stated license, and a public repository cannot ship that.
licenses() {
    local bad
    bad="$(shipped | grep -E '^(references|languages|infrastructure)/' | while read -r f; do
        grep -q " $f\$" "$UPSTREAM" && continue
        head -1 "$SKILL_DIR/$f" | grep -q 'SPDX-License-Identifier: Apache-2.0' && continue
        echo "$f"
    done)"
    if [ -n "$bad" ]; then
        echo "  licenses:         neither an upstream copy nor an SPDX line:"
        echo "$bad" | sed 's/^/    /'
        return 1
    fi
    echo "  licenses:         every guide is an upstream copy or carries its SPDX line"
}

# The CC BY-SA copies are kept byte for byte so that "derived from" stays
# true and an upstream update is a plain copy. A changed copy must be recorded.
upstream_copies() {
    local bad n
    n="$(grep -c '^file ' "$UPSTREAM")"
    bad="$(grep '^file ' "$UPSTREAM" | while read -r _ sum f; do
        [ "$(shasum -a 256 "$SKILL_DIR/$f" 2>/dev/null | cut -c1-64)" = "$sum" ] || echo "$f"
    done)"
    if [ -n "$bad" ]; then
        echo "  upstream copies:  changed since the pin — record it in NOTICE, then update UPSTREAM:"
        echo "$bad" | sed 's/^/    /'
        return 1
    fi
    echo "  upstream copies:  $n, unchanged since $(awk '$1=="commit"{print $2}' "$UPSTREAM")"
}

# A machine path inside a shipped file reaches every clone. The upstream
# copies are skipped: their checksums tie them to upstream, and their Dockerfile
# examples name /root/ on purpose, which reads as $HOME when $HOME is /root.
shipped_leaks() {
    local hits
    # perl, not grep -P: the BSD grep of macOS has no -P.
    hits="$(cd "$SKILL_DIR" && shipped | grep -vxFf <(awk '$1=="file"{print $3}' "$UPSTREAM") | xargs perl -ne 'print "$ARGV:$.:$_" if m{\Q$ENV{HOME}\E/[\w.-]|/home/(?!user\b)[a-z]|/Users/(?!user\b)[a-z]}; close ARGV if eof' || true)"
    if [ -n "$hits" ]; then
        echo "  shipped files:    a path of this machine is named in them:"
        echo "$hits" | sed 's/^/    /'
        return 1
    fi
    echo "  shipped files:    nothing local named in them"
}

check() {
    local v problems=0
    v="$(version)"
    [ -n "$v" ] || { echo "no version: field in $SKILL" >&2; return 3; }
    echo "  SKILL.md version: $v"

    if grep -q "^## $v\( \|$\)" "$LOG"; then
        echo "  CHANGELOG.md:     has a section for $v"
    else
        echo "  CHANGELOG.md:     NO section for $v — add one before tagging"
        problems=1
    fi

    if git -C "$SRC" rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
        echo "  tag v$v:          exists"
        if [ "$(git -C "$SRC" rev-parse "v$v^{commit}")" = "$(git -C "$SRC" rev-parse HEAD)" ]; then
            echo "  HEAD:             at v$v"
        else
            echo "  HEAD:             moved past v$v — release again or reset"
            problems=1
        fi
    else
        echo "  tag v$v:          missing — ./release.sh tag creates it"
        problems=1
    fi

    local orphan untagged
    orphan="$(git -C "$SRC" tag | while read -r tg; do
        grep -q "^## ${tg#v}\( \|$\)" "$LOG" || echo "$tg"
    done)"
    if [ -n "$orphan" ]; then
        echo "  tags with no changelog section:"
        echo "$orphan" | sed 's/^/    /'
        problems=1
    fi
    untagged="$(grep -o '^## [0-9][0-9.]*' "$LOG" | sed 's/^## //' | while read -r s; do
        git -C "$SRC" rev-parse -q --verify "refs/tags/v$s" >/dev/null || echo "$s"
    done)"
    if [ -n "$untagged" ]; then
        echo "  changelog sections with no tag:"
        echo "$untagged" | sed 's/^/    /'
        problems=1
    else
        echo "  changelog sections:  every one has its tag"
    fi

    index || problems=1
    licenses || problems=1
    upstream_copies || problems=1
    shipped_leaks || problems=1
    copies "$v" || problems=1

    if [ "$problems" -eq 0 ]; then
        echo "  agreed and released$([ "$COPIES" -gt 0 ] && echo ", and all $COPIES copies here match")"
        return 0
    fi
    return 3
}

tag() {
    local v body
    v="$(version)"
    if git -C "$SRC" rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
        echo "  tag v$v already exists — a tag is never moved; release a new version" >&2
        return 1
    fi
    grep -q "^## $v\( \|$\)" "$LOG" || {
        echo "  CHANGELOG.md has no section for $v — write it first" >&2
        return 1
    }
    body="$(awk -v v="$v" 'index($0, "## " v) == 1 {f=1; next} f && /^## / {exit} f' "$LOG")"
    git -C "$SRC" tag -a "v$v" -m "$v"$'\n\n'"$body"
    echo "  tagged v$v at $(git -C "$SRC" rev-parse --short HEAD)"
    echo "  push it: git push --follow-tags origin"
}

upstream() {
    local repo path pin latest
    repo="$(awk '$1=="repo"{print $2}' "$UPSTREAM")"
    path="$(awk '$1=="path"{print $2}' "$UPSTREAM")"
    pin="$(awk '$1=="commit"{print $2}' "$UPSTREAM")"
    command -v gh >/dev/null 2>&1 || { echo "  gh not found — compare by hand at https://github.com/$repo/commits/HEAD/$path" >&2; return 2; }
    latest="$(gh api "repos/$repo/commits?path=$path&per_page=1" --jq '.[0].sha')" || return 2
    case "$latest" in
        "$pin"*) echo "  upstream:         $repo $path unchanged since $pin" ;;
        *) echo "  upstream:         moved: pinned $pin, latest ${latest:0:12}"
           echo "                    https://github.com/$repo/compare/$pin...${latest:0:12}"
           return 3 ;;
    esac
}

case "${1:-check}" in
    check)    check ;;
    tag)      tag ;;
    upstream) upstream ;;
    *)        echo "usage: $0 {check|tag|upstream}" >&2; exit 2 ;;
esac
