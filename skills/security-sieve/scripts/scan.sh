#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scan.sh — Step 3 of security-sieve: find the installed scanners, run every
# one of them, and print projections that carry no secret values.
#
#   bash scan.sh <repo-dir> [<out-dir>]
#
# The raw output stays in <out-dir> (a new mktemp directory when omitted) and
# is never printed: trufflehog keeps secret values in `Raw`, semgrep and
# trivy quote source lines. What reaches stdout is a framed summary (also in
# <out-dir>/summary.txt), the tool list, one status line per run, and grouped
# findings: detector or rule, file, line, commit.
#
# A rule in prose was followed or skipped at the model's discretion; a script
# runs every installed tool, every time. Bash 3.2 compatible (macOS).

set -u
repo="${1:?usage: scan.sh <repo-dir> [<out-dir>]}"
cd "$repo" || { echo "scan.sh: cannot enter $repo" >&2; exit 2; }
out="${2:-$(mktemp -d "${TMPDIR:-/tmp}/security-sieve.$(basename "$PWD").XXXXXX")}"
mkdir -p "$out" && chmod 700 "$out"

have() { command -v "$1" >/dev/null 2>&1; }
listed() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }   # <word> <list>
failed="" skipped=""

scan() {
for t in trufflehog gitleaks jq semgrep osv-scanner trivy checkov; do
    if have "$t"; then echo "tool $t ok"; else echo "tool $t missing"; fi
done
# The history sources, one line each: <root> US <path filter> US <label>,
# split on the ASCII unit separator: a tab is IFS whitespace, and bash
# merges two tabs into one, so an empty filter swallowed the label.
# History belongs to a repository, not to the directory under review.
#  - Target inside a repository, even below its root ("CCE/"): the root's
#    history, kept to the target's paths. Cloning file://…/CCE failed (not a
#    repository) and gitleaks read the whole repository's history instead.
#  - Target above repositories (a workspace holding several): each one's
#    whole history, its paths labelled with its directory. Before, such a
#    target read as "no git" and no history was scanned at all.
#  - No .git anywhere: no history exists; the summary says so.
isgit=0 prefix=""
US=$(printf '\037')
if git rev-parse --git-dir >/dev/null 2>&1; then
    prefix=$(git rev-parse --show-prefix)
    printf '%s\037%s\037\n' "$(git rev-parse --show-toplevel)" "$prefix" > "$out/repos.lst"
else
    find . \( -name node_modules -o -name .terraform -o -name vendor \) -prune \
         -o -name .git -prune -print 2>/dev/null | sort | while read -r g; do
        d=${g%/.git}; d=${d#./}
        printf '%s\037\037%s/\n' "$PWD/$d" "$d"
    done > "$out/repos.lst"
fi
nrepos=$(wc -l < "$out/repos.lst" | tr -d ' ')
[ "$nrepos" -gt 0 ] && isgit=1
echo "git-repository=$isgit${prefix:+ subdirectory=$prefix}$([ "$nrepos" -gt 1 ] && echo " repositories=$nrepos")"
# A path is a regex for trufflehog's -i: escape its metacharacters.
rx_escape() { printf '%s' "$1" | sed -e 's/[.*^$+?(){}|]/\\&/g' -e 's/\[/\\[/g' -e 's/]/\\]/g'; }

# One status line per run. A non-zero exit means findings for most of these
# tools, so the verdict is the log: an "error" in it means the run failed.
status() {   # <name> <rc> <seconds> <log>
    local errs=0
    [ -s "$4" ] && errs=$(grep -ci '"level":"error"\|^error\|fatal\|cannot move binary' "$4")
    echo "ran $1 rc=$2 ${3}s log-errors=$errs"
    [ "$errs" -gt 0 ] && case "$1" in
        trufflehog-*) failed="$failed trufflehog" ;;
        gitleaks-*)   failed="$failed gitleaks" ;;
        *)            failed="$failed $1" ;;
    esac
    return 0
}
run() {      # <name> <log> <command…>
    local name="$1" log="$2" s rc
    shift 2
    s=$(date +%s)
    # No tool reads stdin; closing it keeps one from eating the list a
    # surrounding `while read` loop is reading.
    "$@" 2>"$log" </dev/null
    rc=$?
    status "$name" "$rc" "$(( $(date +%s) - s ))" "$log"
}

printf '%s\n' '(^|/)\.git/' '(^|/)(\.terraform|node_modules|vendor|bin|obj)/' > "$out/th-exclude.txt"
TH='{detector: .DetectorName, verified: .Verified,
     where: (.SourceMetadata.Data | to_entries[0].value | {file, line, commit})}'

if have trufflehog && have jq; then
    : > "$out/th-git.ndjson"
    i=0
    # Each clone goes into the scratch directory, never into a repository:
    # nothing this script runs writes inside the target.
    while IFS="$US" read -r rtop rprefix rlabel; do
        i=$((i + 1))
        mkdir -p "$out/clone/$i"
        printf '^%s\n' "$(rx_escape "$rprefix")" > "$out/th-include-$i.txt"
        run "trufflehog-git${rlabel:+:$rlabel}" "$out/th-git-$i.log" \
            sh -c 'exec trufflehog git "file://$1" --clone-path "$2" -i "$3" --no-verification --no-update --json > "$4"' _ \
            "$rtop" "$out/clone/$i" "$out/th-include-$i.txt" "$out/th-git-$i.ndjson"
        jq -c --arg l "$rlabel" '.SourceMetadata.Data.Git.file |= ($l + (. // ""))' \
            "$out/th-git-$i.ndjson" >> "$out/th-git.ndjson" 2>/dev/null
    done < "$out/repos.lst"
    run trufflehog-filesystem "$out/th-fs.log" \
        sh -c 'exec trufflehog filesystem . --no-verification --no-update --json -x "$1" > "$2"' _ \
        "$out/th-exclude.txt" "$out/th-fs.ndjson"
elif have trufflehog; then
    echo "skip trufflehog: jq not installed, its output carries secret values"
    skipped="$skipped trufflehog"
fi

if have gitleaks; then
    i=0
    while IFS="$US" read -r rtop rprefix rlabel; do
        i=$((i + 1))
        run "gitleaks-git${rlabel:+:$rlabel}" "$out/gl-git-$i.log" \
            gitleaks git --no-banner --redact --log-opts="-- ${rprefix:-.}" \
                --report-format json --report-path "$out/gl-git-$i.json" "$rtop"
        # One report for all repositories, each path labelled with its own.
        if have jq; then
            jq -c --arg l "$rlabel" '.[]? | .File = ($l + .File)' "$out/gl-git-$i.json" \
                >> "$out/gl-git.stream" 2>/dev/null
        fi
    done < "$out/repos.lst"
    if [ "$isgit" = 1 ]; then
        if have jq; then
            jq -s '.' "$out/gl-git.stream" > "$out/gl-git.json" 2>/dev/null
        elif [ "$nrepos" -eq 1 ]; then
            cp "$out/gl-git-1.json" "$out/gl-git.json"
        fi
    fi
    run gitleaks-dir "$out/gl-dir.log" \
        gitleaks dir --no-banner --redact --report-format json --report-path "$out/gl-dir.json" .
fi

if have semgrep && have jq; then
    run semgrep "$out/semgrep.log" \
        semgrep scan --config p/default --metrics=off --json --output "$out/semgrep.json" .
elif have semgrep; then
    echo "skip semgrep: jq not installed, its output quotes source lines"
    skipped="$skipped semgrep"
fi
# Offline: the online mode sends every package name and version to
# api.osv.dev. This one downloads the ecosystem's whole database instead
# (~200 MB for npm, into the user cache dir: ~/.cache/osv-scalibr on Linux,
# ~/Library/Caches/osv-scalibr on macOS) and compares locally; on a
# 1444-package lockfile both gave the same 135 vulnerable packages.
have osv-scanner && run osv-scanner "$out/osv.log" \
    sh -c 'exec osv-scanner scan source -r --offline-vulnerabilities --download-offline-databases --format json . > "$1"' _ "$out/osv.json"
if have trivy && have jq; then
    run trivy "$out/trivy.log" \
        trivy fs --scanners vuln,misconfig --format json --output "$out/trivy.json" .
elif have trivy; then
    echo "skip trivy: jq not installed, its output quotes source lines"
    skipped="$skipped trivy"
fi
have checkov && run checkov "$out/checkov.log" \
    sh -c 'exec checkov -d . --compact --quiet -o cli --skip-framework secrets > "$1"' _ "$out/checkov.txt"
}

# The summary: a few lines, framed, before everything else. The model copies
# it into the chat as it is, in a ```diff block, so a run reads green and a
# failure red. Asked to show the `tool`/`ran` lines verbatim instead, the
# model retold them in one sentence and lost which run had failed.
summary() {
    local ok="" bad="" skip="" miss="" t
    for t in trufflehog gitleaks semgrep osv-scanner trivy checkov; do
        if ! have "$t"; then miss="$miss, $t"
        elif listed "$t" "$failed"; then bad="$bad, $t"
        elif listed "$t" "$skipped"; then skip="$skip, $t"
        else ok="$ok, $t"; fi
    done
    have jq || miss="$miss, jq"
    echo "━━━━━━━━━━━━━━ security-sieve: scanners ━━━━━━━━━━━━━━"
    [ -n "$ok" ]   && echo "+ ran      ${ok#, }"
    [ -n "$bad" ]  && echo "- FAILED   ${bad#, }  (errors in its .log)"
    [ -n "$skip" ] && echo "- skipped  ${skip#, }  (no jq)"
    [ -n "$miss" ] && echo "- missing  ${miss#, }"
    [ "$isgit" = 1 ] || echo "- no git   history not scanned"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}
# Colour only for a person at a terminal; the assistant reads a pipe.
paint() {
    if [ -t 1 ]; then
        sed -e $'s/^+.*/\033[32m&\033[0m/' -e $'s/^-.*/\033[31m&\033[0m/'
    else cat; fi
}

scan > "$out/runs.txt"
summary > "$out/summary.txt"
paint < "$out/summary.txt"
echo "out=$out"
cat "$out/runs.txt"

# Projections. No value, no source line: detector or rule, file, line, commit.
have jq || { echo "projections skipped: jq not installed; read $out/gl-*.json (redacted) directly"; exit 0; }
nonempty() { [ -s "$1" ]; }

echo "== secrets: trufflehog (detector, file, hits, commits)"
for f in "$out/th-git.ndjson" "$out/th-fs.ndjson"; do nonempty "$f" && cat "$f"; done |
    jq -c "$TH" 2>/dev/null | jq -s -c 'group_by(.detector, .where.file)
      | map({detector: .[0].detector, file: .[0].where.file, hits: length,
             commits: ([.[].where.commit | select(. != null)] | unique | length)}) | .[]'
echo "== secrets: trufflehog JWT expiry"
for f in "$out/th-git.ndjson" "$out/th-fs.ndjson"; do nonempty "$f" && cat "$f"; done |
    jq -c 'select(.DetectorName == "JWT") | {file: (.SourceMetadata.Data | to_entries[0].value.file),
      exp: (try (.Raw | split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .exp | todate) catch "unreadable")}' 2>/dev/null |
    sort -u
echo "== secrets: gitleaks history (rule, file, hits, commits)"
nonempty "$out/gl-git.json" && jq -c 'group_by(.RuleID, .File) | map({rule: .[0].RuleID, file: .[0].File,
    hits: length, commits: ([.[].Commit] | unique | length)}) | .[]' "$out/gl-git.json"
echo "== secrets: gitleaks working tree (rule, file, hits)"
nonempty "$out/gl-dir.json" && jq -c 'map(select(.File | test("(^|/)(\\.terraform|node_modules|vendor|bin|obj)/") | not))
    | group_by(.RuleID, .File) | map({rule: .[0].RuleID, file: .[0].File, hits: length}) | .[]' "$out/gl-dir.json"
echo "== semgrep (rule, severity, hits, first locations)"
nonempty "$out/semgrep.json" && jq -c '(.results // []) | group_by(.check_id) | map({rule: (.[0].check_id | split(".") | .[-1]),
    severity: .[0].extra.severity, hits: length, at: (map(.path + ":" + (.start.line|tostring)) | .[0:5])}) | .[]' "$out/semgrep.json"
nonempty "$out/semgrep.json" && jq -c '(.errors // []) | map({type: (.type | if type == "array" then .[0] else . end), path: (.spans[0].file // .path // null)}) | .[]' "$out/semgrep.json"
echo "== osv-scanner (package, version, ids)"
nonempty "$out/osv.json" && jq -c '[.results[]?.packages[]? | {package: .package.name, version: .package.version,
    ids: [.vulnerabilities[]?.id]}] | .[]' "$out/osv.json"
echo "== trivy (target, id, severity, package)"
nonempty "$out/trivy.json" && jq -c 'walk(if type == "object" then del(.lines, .Code) else . end)
    | [.Results[]? | .Target as $t | ((.Vulnerabilities // [])[] | {target: $t, id: .VulnerabilityID, severity: .Severity, package: .PkgName}),
                                    ((.Misconfigurations // [])[] | {target: $t, id: .ID, severity: .Severity})] | .[]' "$out/trivy.json"
echo "== checkov (check, file)"
nonempty "$out/checkov.txt" && grep -E '^(Check|[[:space:]]+File):' "$out/checkov.txt" | paste - - | sed -E 's/[[:space:]]+/ /g'
exit 0
