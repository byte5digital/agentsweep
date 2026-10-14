rule as_0019_approvals_or_sandbox_off {
  meta:
    id          = 19
    title       = "Approvals or the sandbox switched off in the user's own settings"
    tier        = 1
    category    = "exposure"
    severity    = "medium"
    class       = 6
    kinds       = "SettingsEntry"
    status      = "probation"
    plain       = "Your agent no longer asks before it does something dangerous, and nothing is holding it back."
    phrase      = "switches off the agent's safety checks"
    description = "A User-scope settings entry that takes the questions away: permissions.defaultMode set to bypassPermissions or dontAsk, skipDangerousModePermissionPrompt set to true, or for Codex approval_policy never or sandbox_mode danger-full-access. Exposure: this is the user's own configuration, never quarantined, offered the RemoveEntry fix action, which removes this one key and leaves the file otherwise as it is. The same keys committed to a repository are rule 0006, a Threat, and the same keys in Managed Scope are the administrator's and stay T2, so this rule reads only User Scope."
    references  = "https://github.com/anthropics/claude-code/security/advisories/GHSA-mmgp-wc2j-qcv7 https://code.claude.com/docs/en/permissions https://learn.chatgpt.com/docs/agent-approvals-security"
    sensitive   = false

  condition:
    item.kind == "SettingsEntry" and item.scope == "user" and (
      (settings.key_path == "permissions.defaultMode"
        and (settings.value == "bypassPermissions" or settings.value == "dontAsk"))
      or (settings.key_path == "skipDangerousModePermissionPrompt" and settings.value == "true")
      or (item.agent == "codex" and (
          (settings.key_path == "approval_policy" and settings.value == "never")
          or (settings.key_path == "sandbox_mode" and settings.value == "danger-full-access")
        ))
    )
}
