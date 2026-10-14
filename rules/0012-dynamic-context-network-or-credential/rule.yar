rule as_0012_dynamic_context_network_or_credential {
  meta:
    id          = 12
    title       = "Dynamic-context span that reaches the network or reads a credential"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill"
    status      = "probation"
    plain       = "This skill runs a command that reaches the internet or reads your login details before anyone has read the skill."
    phrase      = "reaches the internet or your login details as it loads"
    description = "A dynamic-context span in a skill or command file whose command reaches the network (curl, wget, nc, ncat, netcat, socat), encodes or decodes with base64, or reads a credential (gh auth token, security find-generic-password, an SSH private key, the AWS credentials file, the Claude Code or Codex credential file, ~/.claude.json, the GitHub CLI hosts file, ~/.npmrc). A dynamic-context span runs during preprocessing, before the model or the user sees the skill and before workspace trust applies, so the command is the payload. Other dynamic-context commands such as the date or the working tree are documented usage and stay T2; the same command shown in an ordinary code span is not a dynamic-context span and stays silent."
    references  = "https://securitylabs.datadoghq.com/articles/malicious-skills-supply-chain-risks-in-coding-agents-with-dynamic-context/ https://code.claude.com/docs/en/skills"
    sensitive   = false

  strings:
    // !`curl ...`, !`wget ...`, !`nc ...`, !`base64 ...` and their kin
    $dyn_network   = /!`[^`\n]{0,300}(\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bnetcat\b|\bsocat\b|\bbase64\b)/
    // !`gh auth token`, !`security find-generic-password ...`
    $dyn_cred_cmd  = /!`[^`\n]{0,300}(gh\s+auth\s+token|security\s+find-(generic|internet)-password)/
    // !`... ~/.ssh/id_ed25519`, !`... ~/.aws/credentials` and the other credential stores
    $dyn_cred_path = /!`[^`\n]{0,300}(\.ssh\/id_(rsa|dsa|ecdsa|ed25519)|\.aws\/credentials|\.claude\/\.credentials\.json|\.codex\/auth\.json|\.config\/gh\/hosts\.yml|\/\.npmrc|\/\.claude\.json)/

  condition:
    item.file_type == "text" and any of them
}
