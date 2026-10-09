#!/usr/bin/env bash
# Install the security-sieve skill — Linux / macOS.
#
# The skill is Markdown files and nothing else: no binary, no PATH entry, no # runtime. Installing it is a copy into each assistant's skills directory.
#
#   ./install.sh                 install into every assistant found
#   ./install.sh --dry-run       print what would happen, change nothing
#   ./install.sh --skills-dir D  install into D instead of auto-detecting
#
# Idempotent: re-running replaces only what changed. A file it overwrites is
# copied to ~/.local/state/security-sieve-backups ONLY when that content is not
# already in the source repository — a hand edit is the one thing git cannot
# give back. Never beside the file; the three newest copies are kept.
# Nothing outside $HOME is touched.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${SECURITY_SIEVE_BACKUP_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/security-sieve-backups}"

# A copy goes to $BACKUP_DIR, never beside the file: a backup left in a skills
# directory or on PATH loads or runs as part of what it copies. Named by the
# path below $HOME with / turned into _, the three newest kept per file.
backup_file() {
    local dst="$1" name old n=0
    name="${dst#"$HOME"/}"
    name="${name//\//_}"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    cp -p "$dst" "$BACKUP_DIR/$name.bak.$STAMP"
    printf '%s\n' "$BACKUP_DIR/$name".bak.* | sort -r | while IFS= read -r old; do
        n=$((n + 1))
        if [ "$n" -gt 3 ]; then rm -f "$old"; fi
    done
    return 0
}

DRY_RUN=0
SKILLS_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)    DRY_RUN=1 ;;
        --skills-dir) SKILLS_DIR="${2:-}"; shift ;;
        -h|--help)    sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

# Colour only when stdout is a terminal — piping into a log must stay clean.
if [ -t 1 ]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_OFF=$'\033[0m'
else
    C_OK=''; C_WARN=''; C_OFF=''
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s%s%s\n' "$C_OK"   "$*" "$C_OFF"; }
warn() { printf '%s%s%s\n' "$C_WARN" "$*" "$C_OFF"; }
# Not ${1/#$HOME/\~}: bash 3.2, the one macOS ships, keeps the backslash and
# prints \~/.claude — measured in the bash:3.2 image.
tilde() { case "$1" in "$HOME"*) printf '~%s' "${1#"$HOME"}" ;; *) printf '%s' "$1" ;; esac; }

# Is this exact content already in the source repository's object database?
# Then it is one `git checkout` away and a backup of it is worth nothing.
in_git_history() {
    local sha
    command -v git >/dev/null 2>&1 || return 1
    git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1 || return 1
    sha="$(git -C "$SRC" hash-object "$1" 2>/dev/null)" || return 1
    [ -n "$sha" ] && git -C "$SRC" cat-file -e "$sha" 2>/dev/null
}

install_file() {
    local src="$1" dst="$2"
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        say "    = $(tilde "$dst")"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        say "    would write $(tilde "$dst")"
        return 0
    fi
    mkdir -p "$(dirname "$dst")"
    if [ -f "$dst" ]; then
        if in_git_history "$dst"; then
            say "    ~ $(tilde "$dst")"
        else
            backup_file "$dst"
            say "    ~ $(tilde "$dst")  (backup in $(tilde "$BACKUP_DIR") — edited by hand, not in git)"
        fi
    else
        say "    + $(tilde "$dst")"
    fi
    cp "$src" "$dst"
    chmod 644 "$dst"
}

# Only assistants already present are written to — creating a config tree for
# one the person does not have would just litter their home.
detect_skill_dirs() {
    if [ -n "$SKILLS_DIR" ]; then
        printf '%s\n' "$SKILLS_DIR"
        return
    fi
    local d
    for d in "$HOME/.claude/skills" \
             "$HOME/.config/opencode/skills" \
             "$HOME/.codex/skills"; do
        [ -d "$(dirname "$d")" ] && printf '%s\n' "$d"
    done
}

say "── security-sieve ──"
[ "$DRY_RUN" -eq 1 ] && warn "  dry run — nothing will be written"

found=0
while read -r dir; do
    [ -n "$dir" ] || continue
    found=$((found + 1))
    say "  $(tilde "$dir")"
    # Ask the source what it ships rather than listing files here: a fourth
    # reference page added to the skill and forgotten in this list would be
    # missing from every install with nothing to say so.
    while read -r f; do
        install_file "$SRC/skills/security-sieve/$f" "$dir/security-sieve/$f"
    done < <(cd "$SRC/skills/security-sieve" && find . -type f ! -name '*.bak.*' \
             | sed 's|^\./||' | sort)
done < <(detect_skill_dirs)

if [ "$found" -eq 0 ]; then
    warn "  no assistant directory found — nothing installed."
    warn "  Expected one of ~/.claude, ~/.config/opencode, ~/.codex."
    warn "  Point at one yourself: ./install.sh --skills-dir <path>"
    exit 1
fi

say "── verify ──"
rc=0
while read -r dir; do
    [ -n "$dir" ] || continue
    if [ "$DRY_RUN" -eq 1 ]; then
        say "  would verify $(tilde "$dir/security-sieve")"
        continue
    fi
    if grep -q '^name: security-sieve$' "$dir/security-sieve/SKILL.md" 2>/dev/null; then
        ok "  ok — $(tilde "$dir/security-sieve")"
    else
        warn "  FAILED — $(tilde "$dir/security-sieve/SKILL.md") is not the security-sieve skill"
        rc=1
    fi
done < <(detect_skill_dirs)

# The secret scanners are the only way a review sees git history; without them
# a key deleted in an old commit is never found. Say so loudly, every install.
missing=""
for t in trufflehog gitleaks; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
say ""
if [ -n "$missing" ]; then
    warn "  ┌─ STRONGLY RECOMMENDED ─────────────────────────────────────────"
    warn "  │ Not installed:$missing"
    warn "  │ Without trufflehog or gitleaks the review cannot see secrets"
    warn "  │ in git history; reports will say \"NOT scanned\"."
    warn "  │   brew install$missing"
    warn "  │   or: https://github.com/trufflesecurity/trufflehog/releases"
    warn "  │       https://github.com/gitleaks/gitleaks/releases"
    warn "  └────────────────────────────────────────────────────────────────"
else
    ok "  secret scanners: trufflehog and gitleaks found"
fi

say ""
say "  In your assistant: '/security-sieve <what>', or ask for a security review."
say "  With no target inside a git repository it reviews the branch diff."
exit $rc
