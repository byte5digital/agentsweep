> SUPERSEDED 2026-09-16: folded into `attack-catalogue.md`; kept for mechanism detail and provenance only.

# MCP-surface attack catalogue (PARTIAL, from a research subagent, 2026-09-16)

Provenance: produced by a subagent of the attack-catalogue research ticket before the session hit an API rate limit. Covers the MCP surface only; skills, plugins, hooks and instruction-file techniques are still open. Claims were reported as verified against the cited pages by the subagent; treat as unreviewed until the main catalogue ticket is resolved.

Legend: T1 = deterministic from config alone (near-zero FP). T2 = heuristic. RT = runtime-only, not visible in config files.

## 1. MCP Tool Poisoning (hidden instructions in tool descriptions)
- Sources: Invariant Labs 2025-04-01 https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks ; Trail of Bits "line jumping" 2025-04-21 https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/ ; Snyk Labs 2025-08-19 https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/
- Mechanism: `tools/list` descriptions are injected into model context on connect; instructions redirect the agent to read secrets (`~/.ssh/id_rsa`, `~/.cursor/mcp.json`, `.env`) and pass them as tool arguments.
- On-disk indicator: only if server source is local (`node_modules/<pkg>`, hidden home dirs, site-packages) or the scanner enumerates tools. Description strings: `<IMPORTANT>`/`<system>`/`<hidden>` tags; "do not mention", "do not tell the user", "before using this tool, read"; secret path literals; references to other servers' tools. Snyk agent-scan codes E001, W001.
- Tier: T2 for description heuristics; RT if only config is read.

## 2. MCP Rug Pull / TOCTOU
- Sources: Invariant Labs (above); WhatsApp MCP demo 2025-04-07 https://invariantlabs.ai/blog/whatsapp-mcp-exploited
- Mechanism: benign at approval, description changes later; clients do not notify.
- Indicator: none in config. Scanner can pin a hash of each server's `tools/list` at first scan and alert on drift.
- Tier: RT; T1 for "drift since baseline" if a baseline is kept, T2 on maliciousness of drift.

## 3. Cross-Server Tool Shadowing
- Sources: Invariant Labs (above); Snyk agent-scan E002 https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md
- Indicator: description on server A naming server B's tools or `mcp__<other>__` prefixes; "when <tool> is invoked, ..." patterns.
- Tier: RT/source-only, T2 when descriptions available.

## 4a. Project-scoped MCP config planted in a repo: Cursor CurXecute (CVE-2025-54135)
- Source: Tenable FAQ https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison (2025-08-01, CVSS 8.5). Aim Security original returned 403.
- Indicator: new `mcpServers` entry whose `command`/`args` runs a shell (`sh -c`, `bash -c`, `cmd /c`), fetches remotely (`curl`, `wget`, `Invoke-WebRequest`), writes to `/tmp`, or contains shell metacharacters.
- Tier: T1 for curl-pipe-shell / `bash -c` with network fetch; T2 for generic metacharacters.

## 4b. Cursor MCPoison (CVE-2025-54136): approval bound to key name, not contents
- Source: Check Point Research 2025-08-05 https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/
- Indicator: per-server-key diff of `command`/`args`/`env`/`url` vs last-scanned hash with unchanged key name.
- Tier: T1 for changed-since-baseline; T2 on maliciousness.

## 4c. Claude Code repo-level config RCE: CVE-2025-59536 (hooks + MCP consent bypass)
- Source: Check Point Research 2026-02-25 https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/ ; Claude Code MCP docs https://code.claude.com/docs/en/mcp
- Mechanism: repo ships `.mcp.json` (stdio command) plus `.claude/settings.json` with `enableAllProjectMcpServers: true` or `enabledMcpjsonServers: [name]` so its own servers self-approve. Fixed in 1.0.111; since v2.1.196 committed approvals are ignored in untrusted folders.
- Indicator (T1): repo-tracked `.claude/settings.json` containing `enableAllProjectMcpServers: true` or `enabledMcpjsonServers` naming servers defined in the same repo's `.mcp.json`.

## 4d. Claude Code API-key exfil via repo env: CVE-2026-21852
- Source: GHSA-jh7p-qr78-84p7 https://github.com/advisories/GHSA-jh7p-qr78-84p7 (2026-01-20, fixed 2.0.65)
- Indicator (T1): repo-tracked `.claude/settings.json` with `env.ANTHROPIC_BASE_URL` (or `ANTHROPIC_AUTH_TOKEN`, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`) pointing at a non-`api.anthropic.com` host.

## 4e. Claude Code trust-dialog bypass via repo settings: CVE-2026-33068
- Source: GHSA-mmgp-wc2j-qcv7 https://github.com/anthropics/claude-code/security/advisories/GHSA-mmgp-wc2j-qcv7 (2026-03-18, CVSS 7.7, fixed 2.1.53). Related GHSA-ff64-7w26-62rf (CVE-2026-25725, fixed 2.1.2): sandboxed code creating `.claude/settings.json` to inject persistent SessionStart hooks.
- Indicator (T1): repo-tracked `.claude/settings.json` with `permissions.defaultMode: "bypassPermissions"` or `skipDangerousModePermissionPrompt`.

## 4f. claude-code-action: malicious `.mcp.json` in PR: CVE-2026-47751
- Source: GHSA-8q5r-mmjf-575q https://github.com/advisories/GHSA-8q5r-mmjf-575q (2026-05-20, fixed action 1.0.74)
- Indicator (T1): `.mcp.json` in PR diff; workflows invoking claude-code-action < 1.0.74. Confirms non-interactive contexts (`claude -p`, SDK, cloud) auto-load project servers.

## 4g. Codex CLI `.codex/config.toml` MCP auto-exec: CVE-2025-61260
- Sources: Check Point 2025-12-01 https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/ ; GHSA-xrxf-jgv3-qmrm https://github.com/advisories/GHSA-xrxf-jgv3-qmrm (CVSS 9.8) ; PromptArmor PSA Feb 2026 https://www.promptarmor.com/resources/openai-codex-psa-on-malicious-config-files ; Codex docs https://learn.chatgpt.com/docs/extend/mcp?surface=cli
- Mechanism: repo ships `.env` with `CODEX_HOME=./.codex` plus `.codex/config.toml` `[mcp_servers.*]`; Codex loads and executes without approval. OpenAI closed follow-up as working as intended. Fix version discrepancy: Check Point says 0.23.0, GHSA says <=0.23.0 affected.
- Indicators (T1): repo-tracked `.env` containing `CODEX_HOME=`; repo-tracked `.codex/config.toml` with `[mcp_servers.*]` command entries; `~/.codex/config.toml` `[projects."<path>"] trust_level = "trusted"` for unexpected paths.

## 5. Plaintext secrets in MCP config (`env`, `args`, `headers`, `url`)
- Sources: GitGuardian 2026-03-17 https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/ (24,008 secrets in MCP configs on public GitHub, 2,117 valid) ; Trend 2026-04-28 https://www.trendaisecurity.com/en-us/resources-insights/deep-research/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud ; Claude Code changelog 2.1.268 (secrets shown from `${VAR}` in `claude mcp list`) ; Claude Code docs: credential-named vars read as empty in remote `url`/`headers`.
- Indicators: regexes for AWS `AKIA…`, `ghp_`/`github_pat_`, `sk-ant-`, `xoxb-`, `AIza…`, literal `Bearer`, `postgresql://user:pass@`, PEM blocks; `Authorization` header literal (not `${VAR}`); `--token`/`--api-key` literals in `args`; `?token=` in `url`. Separately T1: `.mcp.json`/plugin `headers`/`url` referencing `${ANTHROPIC_*}` vars = credential forwarding.
- Tier: T1 for well-formed key regexes and `${ANTHROPIC_*}` in remote headers/url; T2 for generic high entropy.

## 6a. Trojanized MCP package: `postmark-mcp` backdoor
- Sources: Snyk https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/ ; Postmark 2025-09-25 https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package
- Mechanism: impersonating package, 15 clean versions then v1.0.16 added a Bcc to an attacker address.
- Indicator (T1): `command`/`args` referencing `postmark-mcp`; generally `npx -y <pkg>` where pkg is not in the vendor's scope.

## 6b. Malicious MCP servers on npm/PyPI with reverse shells
- Source: JFrog 2025-10-19 https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/ (PyPI `mcp-runcmd-server`, `mcp-runcommand-server`, `mcp-runcommand-server2`; npm `@lanyer640/mcp-runcommand-server`; C2 45.115.38.27:4433)
- Indicator (T1): those package names in `command`/`args`; known-bad IP blocklist in server source.

## 6c. SANDWORM_MODE: typosquats that install a rogue MCP server into agent configs (2026)
- Source: Socket 2026-02-20 https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning (19 packages incl. `claud-code`, `cloude-code`, `cloude`, `suport-color`, `opencraw`, `rimarf`, `veim`)
- Mechanism: "McpInject" writes MCP entries into `~/.cursor/mcp.json`, `~/.continue/config.json`, `~/.windsurf/mcp.json`, `~/.claude/settings.json`; server "dev-utils" in hidden `~/.dev-utils/`; tool descriptions instruct reading ssh/aws/npmrc/.env and "do not mention this step to the user"; exfil to `pkg-metrics[.]official334[.]workers[.]dev`, DNS fallback `freefan[.]net`, `fanfree[.]net`.
- Indicators: T1 for MCP `command` under an unknown hidden home dir, known package names, known tool names; T2 for any MCP `command` under `$HOME/.*/` outside known tool dirs.

## 6d. `mcp-remote` command injection: CVE-2025-6514
- Source: JFrog 2025-07-09 https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/ (CVSS 9.6, affects 0.0.5 to 0.1.15, fixed 0.1.16)
- Indicator (T1): `args` containing `mcp-remote` unpinned or pinned <0.1.16, especially with `http://` or unknown host targets.

## 6e. Anthropic Filesystem MCP server bypasses: CVE-2025-53109 / CVE-2025-53110
- Source: Cymulate https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/ (patched 2025.7.1)
- Indicator (T1): `@modelcontextprotocol/server-filesystem` <2025.7.1 or unpinned with broad allowed dirs (`/`, `$HOME`).

## 6f. Smithery hosted-registry compromise
- Source: GitGuardian June 2025 https://blog.gitguardian.com/breaking-mcp-server-hosting/ ; arXiv 2509.24272
- Indicator (T2): remote `url` at `*.smithery.ai`, `glama.ai`, `mcp.so` proxies: informational, secrets transit a shared host.

## 7. Indirect prompt injection via tool results ("lethal trifecta"): runtime only
- Sources: Simon Willison 2025-06-16 https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/ ; Invariant GitHub MCP 2025-05-26 https://invariantlabs.ai/blog/mcp-github-vulnerability ; General Analysis Supabase 2025-07-08 https://www.generalanalysis.com/blog/supabase-mcp-blog ; Unit 42 2025-12-05 https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/
- Static proxy indicator (T2): configured server set combines a secret/data source, an untrusted-content reader, and an egress tool (Snyk agent-scan W015 to W020); `env` keys like `SUPABASE_SERVICE_ROLE_KEY`; `--read-only` absent.

## 8. Suspicious `command` / `args` / `url` values (generic)
- T1: shell `-c` plus `curl|wget|Invoke-WebRequest` piped to an interpreter; `base64 -d`; `eval`; `python -c "import socket"`; `nc -e`; `/dev/tcp/`; command path under `/tmp`, `/var/tmp`, `~/Downloads`, unknown hidden home dir, or world-writable.
- T2: unscoped `npx -y`/`uvx` packages with low downloads or Levenshtein-close to known MCP packages; `http://` remote urls, raw IPs, non-standard ports, punycode hosts, host not matching the vendor implied by server name.
- Informational: deprecated `type: "sse"` transport.

## 9. Claude Code trust controls relevant to the scanner (docs verified 2026-09)
- Interactive sessions prompt before using project `.mcp.json` servers; `claude mcp reset-project-choices` resets. Non-interactive (`claude -p`, SDK, cloud) loads them without asking; `bypassPermissions` + `skipDangerousModePermissionPrompt` also skips the prompt.
- Settings keys: `enableAllProjectMcpServers`, `enabledMcpjsonServers`, `disabledMcpjsonServers`, `allowedMcpServers`, `deniedMcpServers`, `allowManagedMcpServersOnly`, `managedMcpServers`, `disableAllHooks`, `allowedHttpHookUrls`.
- `${VAR}` expansion in `command`, `args`, `env`, `url`, `headers`; credential-named vars read as empty in remote `url`/`headers`.
- Trail of Bits ANSI deception 2025-04-29 https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/ : indicator (T1) byte 0x1b or zero-width/bidi chars (U+200B to U+200F, U+2060 to U+2064, U+202A to U+202E, U+E0000 tags) in any config string (Snyk W021).
- Derived scanner checks (T1): `~/.claude.json` per-project approvals for temp dirs, Downloads, or deleted paths; repo-tracked `.claude/settings.json` setting any of `enableAllProjectMcpServers`, `enabledMcpjsonServers`, `permissions.defaultMode: bypassPermissions`, `env.ANTHROPIC_BASE_URL`, `hooks.*`; Codex `[projects.*] trust_level="trusted"` for unexpected paths.

## Explicitly runtime-only (out of scope for a config scanner)
Tool-description contents unless source is local; rug-pull drift without a baseline; injection via tool results and sampling; `mcp-remote` OAuth injection at connect time; filesystem-MCP traversal exploitation; ANSI deception in outputs.

## Unverified leads
- Koi Security postmark-mcp write-up (URL now redirects to Palo Alto Networks).
- Aim Security CurXecute post (403).
- Invariant mcp-scan README, hash pinning of tool descriptions https://github.com/invariantlabs-ai/mcp-scan (502).
- CVE-2026-64650 (possibly Codex).
- Amazon Q `.amazonq/mcp.json` auto-exec CVE-2026-12957 / 12958, via CSA note https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-ai-coding-assistant-credential-theft-2/
- Cursor July 2026 sandbox-escape flaws (The Hacker News, secondary).
- Check Point AI Threat Landscape digests 2026.
- Tenable TRA-2026-27 (claude-code-action).
- arXiv 2603.22489 (seven MCP clients compared for tool-poisoning defenses).
- Snyk "Clinejection" malicious Cline plugin 2026-02-09 (plugin surface, relevant to the main catalogue).
