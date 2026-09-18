rule as_0007_agent_repointed {
  meta:
    id          = 7
    title       = "Agent re-pointed to another configuration directory or API host"
    tier        = 1
    category    = "threat"
    severity    = "high"
    class       = 2
    kinds       = "EnvFile,SettingsEntry"
    status      = "probation"
    plain       = "A file in this project tells the agent to load its configuration from somewhere else or to talk to a different server."
    description = "CLAUDE_CONFIG_DIR or CODEX_HOME set in any scanned .env file or settings env block (there is no legitimate reason for a project or a settings file to relocate the agent's home; CVE-2025-61260), or a git-tracked .env file setting ANTHROPIC_BASE_URL, OPENAI_BASE_URL, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_API_KEY or NODE_OPTIONS. Untracked .env files with a base URL are common for local model servers and stay T2; a base URL in the user's own settings is an Exposure. EnvFile is a never-auto kind, so this rule flags with a one-click fix."
    references  = "https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/ https://github.com/advisories/GHSA-xrxf-jgv3-qmrm https://github.com/advisories/GHSA-jh7p-qr78-84p7"
    sensitive   = true

  condition:
    (item.kind == "EnvFile" and (
        for any k in env.keys: (k == "CLAUDE_CONFIG_DIR" or k == "CODEX_HOME")
        or (item.provenance == "repository" and for any k in env.keys: (
            k == "ANTHROPIC_BASE_URL" or k == "OPENAI_BASE_URL" or k == "ANTHROPIC_AUTH_TOKEN"
            or k == "ANTHROPIC_API_KEY" or k == "NODE_OPTIONS"))
      ))
    or (item.kind == "SettingsEntry" and settings.key_path matches /^env\.(CLAUDE_CONFIG_DIR|CODEX_HOME)$/)
}
