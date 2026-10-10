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
isgit=0
git rev-parse --git-dir >/dev/null 2>&1 && isgit=1
echo "git-repository=$isgit"

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
    "$@" 2>"$log"
    rc=$?
    status "$name" "$rc" "$(( $(date +%s) - s ))" "$log"
}

printf '%s\n' '(^|/)\.git/' '(^|/)(\.terraform|node_modules|vendor|bin|obj)/' > "$out/th-exclude.txt"
TH='{detector: .DetectorName, verified: .Verified,
     where: (.SourceMetadata.Data | to_entries[0].value | {file, line, commit})}'

if have trufflehog && have jq; then
    [ "$isgit" = 1 ] && run trufflehog-git "$out/th-git.log" \
        sh -c 'exec trufflehog git file://. --no-verification --no-update --json > "$1"' _ "$out/th-git.ndjson"
    run trufflehog-filesystem "$out/th-fs.log" \
        sh -c 'exec trufflehog filesystem . --no-verification --no-update --json -x "$1" > "$2"' _ \
        "$out/th-exclude.txt" "$out/th-fs.ndjson"
elif have trufflehog; then
    echo "skip trufflehog: jq not installed, its output carries secret values"
    skipped="$skipped trufflehog"
fi

if have gitleaks; then
    [ "$isgit" = 1 ] && run gitleaks-git "$out/gl-git.log" \
        gitleaks git --no-banner --redact --report-format json --report-path "$out/gl-git.json" .
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
have osv-scanner && run osv-scanner "$out/osv.log" \
    sh -c 'exec osv-scanner scan source -r --format json . > "$1"' _ "$out/osv.json"
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
