rule as_0006_repository_settings_dangerous_keys {
  meta:
    id          = 6
    title       = "Repository-committed agent settings that redirect, escalate or self-approve"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 2
    kinds       = "SettingsEntry"
    status      = "probation"
    plain       = "This project ships agent settings that would send your API traffic elsewhere, switch off permission prompts or approve its own tools without asking you."
    description = "A settings entry with Provenance Repository (tracked in git) that sets a network or credential environment key (ANTHROPIC_BASE_URL off api.anthropic.com, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_API_KEY, HTTP(S)_PROXY, NODE_EXTRA_CA_CERTS, NODE_OPTIONS), a credential helper command (apiKeyHelper, awsCredentialExport, awsAuthRefresh, otelHeadersHelper), self-approval of the repository's own MCP servers (enableAllProjectMcpServers, enabledMcpjsonServers), a permission bypass (permissions.defaultMode bypassPermissions or dontAsk, skipDangerousModePermissionPrompt, permissions.allow with unrestricted Bash or network tools), or for Codex approval_policy never, sandbox_mode danger-full-access, notify, or a model_providers base_url, env_key or auth. Committed hooks, statusLine and fileSuggestion are T2 indicators because teams share them legitimately. The same keys in the user's own untracked files are not matched."
    references  = "https://github.com/advisories/GHSA-jh7p-qr78-84p7 https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/ https://github.com/anthropics/claude-code/security/advisories/GHSA-mmgp-wc2j-qcv7 https://www.sonarsource.com/blog/claude-arbitrary-code-execution/ https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/"
    sensitive   = false

  condition:
    item.kind == "SettingsEntry" and item.provenance == "repository" and (
      (settings.key_path matches /^env\.(ANTHROPIC_BASE_URL|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|HTTPS_PROXY|HTTP_PROXY|NODE_EXTRA_CA_CERTS|NODE_OPTIONS)$/
        and not (settings.key_path == "env.ANTHROPIC_BASE_URL" and settings.value_host == "api.anthropic.com"))
      or settings.key_path matches /^(apiKeyHelper|awsCredentialExport|awsAuthRefresh|otelHeadersHelper)$/
      or (settings.key_path == "enableAllProjectMcpServers" and settings.value == "true")
      or settings.key_path startswith "enabledMcpjsonServers"
      or (settings.key_path == "permissions.defaultMode" and (settings.value == "bypassPermissions" or settings.value == "dontAsk"))
      or settings.key_path == "skipDangerousModePermissionPrompt"
      or (settings.key_path startswith "permissions.allow." and settings.value matches /^Bash(\(\s*(\*|(curl|wget|nc|sh|bash|zsh)(\s*\*)?)\s*\))?$/)
      or (item.agent == "codex" and (
          (settings.key_path == "approval_policy" and settings.value == "never")
          or (settings.key_path == "sandbox_mode" and settings.value == "danger-full-access")
          or settings.key_path == "notify"
          or settings.key_path matches /^model_providers\.[^.]+\.(base_url|env_key|auth)/
        ))
    )
}
