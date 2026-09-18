rule as_0002_reverse_shell_and_permission_bypass {
  meta:
    id          = 2
    title       = "Reverse shell primitive or agent permission bypass"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent"
    status      = "probation"
    plain       = "This file tries to open a remote control channel or to run an agent with all safety checks switched off."
    description = "Reverse-shell idioms (nc -e, socat exec:, interactive shell redirected to /dev/tcp, mkfifo pipelines, python socket one-liners) in any scanned text, an executable surface that spawns an agent CLI with its permission or sandbox bypass flag, or a third-party subagent definition that declares permissionMode bypassPermissions. Bypass flags are not matched in instruction files, where they can be documented legitimately; unrestricted allowed-tools in skills and bare /dev/tcp port checks are T2 indicators, not part of this rule."
    references  = "https://labs.reversec.com/posts/2026/05/skill-issues-compromising-claude-code-with-malicious-skills-agents-part-1 https://www.wiz.io/blog/s1ngularity-supply-chain-attack https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/"
    sensitive   = false

  strings:
    $shell_nc_e      = /\bn(c|cat|etcat)\s[^\n]{0,120}\s-e\s*\/bin\/(ba|z)?sh\b/
    $shell_socat     = /\bsocat\s[^\n]{0,200}exec:['"]?\/bin\/(ba|z)?sh/
    $shell_devtcp_i  = /(ba|z)?sh\s+-i\s*>&\s*\/dev\/(tcp|udp)\//
    $shell_devtcp_01 = /\/dev\/(tcp|udp)\/[^\s\/]+\/[0-9]+\s+0>&1/
    $shell_mkfifo    = /\bmkfifo\s[^\n]{0,80}\|\s*(\/bin\/)?(ba)?sh\s[^\n]{0,80}\|\s*n(c|cat)\b/
    $shell_py_socket = /\bpython3?\s+-c\s+["'][^\n"']{0,200}import\s+(socket|pty)/
    $flag_claude     = /\bclaude\s[^\n]{0,200}(--dangerously-skip-permissions|--permission-mode[\s=]+bypassPermissions)/
    $flag_codex      = /\bcodex\s[^\n]{0,200}--dangerously-bypass-approvals-and-sandbox\b/
    $flag_hook_trust = "--dangerously-bypass-hook-trust"
    $flag_gemini     = /\bgemini\s[^\n]{0,200}--yolo\b/
    $flag_q          = /\bq\s+chat\s[^\n]{0,200}--trust-all-tools\b/

  condition:
    any of ($shell_*)
    or (item.kind != "InstructionFile" and any of ($flag_*))
    or (item.kind == "Subagent" and item.provenance != "manual" and subagent.permission_mode == "bypassPermissions")
}
