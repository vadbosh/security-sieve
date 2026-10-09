<#
Install the security-sieve skill — Windows (PowerShell 5.1 or 7).
Linux / macOS: use install.sh

The skill is Markdown files and nothing else: no binary, no PATH entry, no
runtime. Installing it is a copy into each assistant's skills directory.

    .\install.ps1                 install into every assistant found
    .\install.ps1 -DryRun         print what would happen, change nothing
    .\install.ps1 -SkillsDir D    install into D instead of auto-detecting

Idempotent: re-running replaces only what changed. A file it overwrites is
copied to %LOCALAPPDATA%\security-sieve-backups ONLY when that content is not
already in the source repository — a hand edit is the one thing git cannot
give back. Never beside the file; the three newest copies are kept.
Nothing outside your profile is touched unless -SkillsDir points there.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$SkillsDir
)

$ErrorActionPreference = 'Stop'
$Src      = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillSrc = Join-Path (Join-Path $Src 'skills') 'security-sieve'
$Stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$Sep      = [IO.Path]::DirectorySeparatorChar

# An empty value must not fall back to auto-detection: a wrapper passing an
# unset variable would install into every assistant on the machine.
if ($PSBoundParameters.ContainsKey('SkillsDir') -and -not $SkillsDir) {
    Write-Host '-SkillsDir needs a path' -ForegroundColor Red
    exit 2
}

function Say   { param($m) Write-Host $m }
function Ok    { param($m) Write-Host $m -ForegroundColor Green }
function Warn  { param($m) Write-Host $m -ForegroundColor Yellow }
function Tilde { param($p) $p -replace "^$([regex]::Escape($HOME))", '~' }

# A copy goes to $BackupDir, never beside the file: a backup left in a skills
# directory loads as part of the skill. Named by the path below the profile
# with the separators turned into _, the three newest kept per file.
$BackupDir = if ($env:SECURITY_SIEVE_BACKUP_DIR) { $env:SECURITY_SIEVE_BACKUP_DIR }
             elseif ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'security-sieve-backups' }
             else { Join-Path $HOME '.local/state/security-sieve-backups' }
function Backup-File ([string]$Path) {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    $full = [IO.Path]::GetFullPath($Path)
    $rel  = if ($full.StartsWith("$HOME$Sep", [StringComparison]::OrdinalIgnoreCase)) {
                $full.Substring($HOME.Length + 1) } else { $full -replace '^([A-Za-z]:)?[\\/]', '' }
    # No leading dot: a plain listing of the backup directory hides dot files.
    $name = ($rel -replace '[\\/]', '_') -replace '^\.', ''
    Copy-Item -LiteralPath $Path -Destination (Join-Path $BackupDir "$name.bak.$Stamp") -Force
    Get-ChildItem -Force -LiteralPath $BackupDir -Filter "$name.bak.*" |
        Sort-Object Name -Descending | Select-Object -Skip 3 | Remove-Item -Force
}

# Is this exact content already in the repository's object database? Then it
# is one `git checkout` away and a backup of it is worth nothing.
function In-GitHistory ([string]$Path) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return $false }
    $sha = & git -C $Src hash-object $Path 2>$null
    if (-not $sha) { return $false }
    & git -C $Src cat-file -e $sha 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Install-File ([string]$From, [string]$To) {
    if ((Test-Path -LiteralPath $To) -and
        ((Get-FileHash -LiteralPath $From).Hash -eq (Get-FileHash -LiteralPath $To).Hash)) {
        Say "    = $(Tilde $To)"
        return
    }
    if ($DryRun) { Say "    would write $(Tilde $To)"; return }
    $dir = Split-Path -Parent $To
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path -LiteralPath $To) {
        if (In-GitHistory $To) {
            Say "    ~ $(Tilde $To)"
        } else {
            Backup-File $To
            Say "    ~ $(Tilde $To)  (backup in $(Tilde $BackupDir) — edited by hand, not in git)"
        }
    } else {
        Say "    + $(Tilde $To)"
    }
    Copy-Item -LiteralPath $From -Destination $To -Force
}

# Only assistants already present are written to — creating a config tree for
# one the person does not have would just litter their profile. The three
# paths are the same on Windows as elsewhere: each assistant resolves them
# from the home directory.
function Get-SkillDirs {
    if ($SkillsDir) { return @($SkillsDir) }
    @(
        (Join-Path (Join-Path $HOME '.claude') 'skills'),
        (Join-Path (Join-Path (Join-Path $HOME '.config') 'opencode') 'skills'),
        (Join-Path (Join-Path $HOME '.codex') 'skills')
    ) | Where-Object { Test-Path -LiteralPath (Split-Path -Parent $_) }
}

Say '── security-sieve ──'
if ($DryRun) { Warn '  dry run — nothing will be written' }

$dirs = @(Get-SkillDirs)
if ($dirs.Count -eq 0) {
    Warn '  no assistant directory found — nothing installed.'
    Warn '  Expected one of ~\.claude, ~\.config\opencode, ~\.codex.'
    Warn '  Point at one yourself: .\install.ps1 -SkillsDir <path>'
    exit 1
}

# Ask the source what it ships rather than listing files here: a guide added to
# the skill and forgotten in a list would be missing from every install.
$shipped = @(Get-ChildItem -LiteralPath $SkillSrc -Recurse -File |
             Where-Object { $_.Name -notlike '*.bak.*' } |
             ForEach-Object { $_.FullName.Substring($SkillSrc.Length + 1) })

foreach ($dir in $dirs) {
    Say "  $(Tilde $dir)"
    $dest = Join-Path $dir 'security-sieve'
    foreach ($rel in $shipped) {
        Install-File (Join-Path $SkillSrc $rel) (Join-Path $dest $rel)
    }
    # A file the source no longer ships would still be loaded by the assistant.
    # Report it; the directory is the assistant's, so it is not deleted here.
    # CAPABILITIES.md is generated there by the host.
    if (Test-Path -LiteralPath $dest) {
        Get-ChildItem -LiteralPath $dest -Recurse -File |
            Where-Object { $_.Name -notlike '*.bak.*' -and $_.Name -ne 'CAPABILITIES.md' } |
            ForEach-Object {
                $rel = $_.FullName.Substring($dest.Length + 1)
                if ($shipped -notcontains $rel) {
                    Warn "    ! $(Tilde $_.FullName)  not in the source — stale, remove it by hand"
                }
            }
    }
}

Say '── verify ──'
$rc = 0
foreach ($dir in $dirs) {
    $skill = Join-Path (Join-Path $dir 'security-sieve') 'SKILL.md'
    if ($DryRun) { Say "  would verify $(Tilde $skill)"; continue }
    if ((Test-Path -LiteralPath $skill) -and (Select-String -LiteralPath $skill -Pattern '^name: security-sieve$' -Quiet)) {
        Ok "  ok — $(Tilde (Split-Path -Parent $skill))"
    } else {
        Warn "  FAILED — $(Tilde $skill) is not the security-sieve skill"
        $rc = 1
    }
}

# The secret scanners are the only way a review sees git history; without them
# a key deleted in an old commit is never found. Say so loudly, every install.
$missing = @('trufflehog', 'gitleaks') | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
Say ''
# Claude Code on Windows runs the Bash tool through Git Bash; without Git for
# Windows it uses PowerShell, and the scanner commands in the skill (bash) do
# not run. The review then reads the code only. Say so before anyone relies on it.
if (-not (Get-Command bash -ErrorAction SilentlyContinue)) {
    Warn '  ┌─ BASIC REVIEW ON THIS MACHINE ─────────────────────────────────'
    Warn '  │ No bash found. The skill runs its scanners through bash (Git'
    Warn '  │ Bash on Windows), so here it reads the code only: no scanners,'
    Warn '  │ and secrets in git history are NOT scanned. Reports say so.'
    Warn '  │ Full review: install Git for Windows, then the scanners below.'
    Warn '  │   https://git-scm.com/downloads/win'
    Warn '  └────────────────────────────────────────────────────────────────'
}
if ($missing) {
    Warn '  ┌─ STRONGLY RECOMMENDED ─────────────────────────────────────────'
    Warn "  │ Not installed: $($missing -join ' ')"
    Warn '  │ Without trufflehog or gitleaks the review cannot see secrets'
    Warn '  │ in git history; reports will say "NOT scanned".'
    Warn '  │   https://github.com/trufflesecurity/trufflehog/releases'
    Warn '  │   https://github.com/gitleaks/gitleaks/releases'
    Warn '  └────────────────────────────────────────────────────────────────'
} else {
    Ok '  secret scanners: trufflehog and gitleaks found'
}
if (-not (Get-Command jq -ErrorAction SilentlyContinue)) {
    foreach ($t in @('trufflehog', 'semgrep', 'trivy')) {
        if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { continue }
        Warn "  jq is not installed: the skill skips $t, whose raw output can carry"
        Warn '  secret values or source lines. Install jq to use it.'
    }
}

Say ''
Say "  In your assistant: '/security-sieve <what>', or ask for a security review."
Say '  With no target inside a git repository it reviews the branch diff.'
exit $rc
