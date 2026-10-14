rule as_0567_managed_scope_redirect {
  meta:
    id          = 567
    title       = "Managed settings send the traffic elsewhere, or run a hook AgentSweep cannot touch"
    tier        = 2
    weight      = 3
    category    = "threat"
    severity    = "high"
    class       = 3
    kinds       = "SettingsEntry,Hook"
    status      = "stable"
    plain       = "Settings your organisation controls send the agent's traffic to another server, or run a command on every session. AgentSweep cannot change them, so contact your administrator if this is news to you."
    phrase      = "sends traffic elsewhere or runs a command you cannot change"
    description = "Managed Scope is the highest layer of both agents and the one AgentSweep may only read: a managed hook is trusted unconditionally and runs before anything else, and a managed base URL puts a hop of the administrator's choosing between the user and the vendor. That is ordinary in a managed fleet, and also exactly what someone who reached the managed directory would write, and the user cannot tell the two apart from the outside. So the Finding is never a Quarantine and never an instruction to edit the file; it names what is set and says to contact the administrator. A managed base URL on the vendor's own host or on this machine stays silent, and so does the same hook in the user's own settings, which is 0562 and 0563's ground."
    references  = "https://code.claude.com/docs/en/managed-settings docs/research/claude-code-surfaces.md docs/research/codex-surfaces.md"
    sensitive   = true

  condition:
    item.scope == "managed" and (
      item.kind == "Hook"
      or (item.kind == "SettingsEntry"
          and settings.key_path matches /(^|\.)(ANTHROPIC_BASE_URL|ANTHROPIC_VERTEX_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|openai_base_url|chatgpt_base_url|base_url)$/
          and settings.value_host != ""
          and not (settings.value_host matches /^(api\.anthropic\.com|api\.openai\.com|chatgpt\.com|127\.0\.0\.1|localhost|0\.0\.0\.0|::1)$/))
    )
}
