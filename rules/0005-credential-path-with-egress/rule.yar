import "math"

rule as_0005_credential_path_with_egress {
  meta:
    id          = 5
    title       = "Credential file named next to a network or copy command"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 4
    kinds       = "InstructionFile,Skill,Hook,Subagent,Plugin"
    status      = "probation"
    plain       = "This file points the agent at your private keys or login tokens and at a way to send them somewhere."
    description = "A private credential store (SSH private key, AWS credentials, the Claude Code or Codex credential files, ~/.claude.json, the GitHub CLI hosts file, ~/.npmrc, a macOS Keychain dump) named within 300 bytes of a network transfer or DNS command used as a command (curl, wget, nc, scp, rsync, sftp, ping, nslookup, dig, whois, Invoke-WebRequest). Public key files (.pub) and .env files are excluded because setup documentation legitimately mentions them; priority language alone is a T2 indicator."
    references  = "https://www.backslash.security/blog/openai-codex-injection-in-agents-md-exfiltrating-credentials https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/ https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-developer-supply-chain-codexui-20260601/"
    sensitive   = false

  strings:
    $cred_ssh_private = /\.ssh\/id_(rsa|dsa|ecdsa|ed25519)\b[^.]/
    $cred_aws         = /\.aws\/credentials\b/
    $cred_claude      = /\.claude\/\.credentials\.json/
    $cred_claude_json = /(~|\$HOME|\/Users\/[^\/\s]{1,64})\/\.claude\.json\b/
    $cred_codex       = /\.codex\/auth\.json/
    $cred_gh          = /\.config\/gh\/hosts\.yml/
    $cred_npmrc       = /(~|\$HOME)\/\.npmrc\b/
    $cred_keychain    = /security\s+find-(generic|internet)-password/
    $egress           = /[\n`$(|;&\s](curl|wget|nc|ncat|netcat|scp|rsync|sftp|ping|nslookup|dig|whois|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+[-\w.\/$"'{]/

  condition:
    item.file_type == "text"
    and for any i in (1..#egress): (
      for any of ($cred_*): ($ in (math.max(@egress[i], 300) - 300..@egress[i] + 300))
    )
}
