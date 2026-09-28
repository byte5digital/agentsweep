rule as_0589_trust_without_session_history {
  meta:
    id          = 589
    title       = "A project whose configuration loads although nobody has worked in it"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 2
    kinds       = "SettingsEntry"
    status      = "stable"
    plain       = "This folder's settings are switched on although the agent has never been used in it."
    description = "A context Heuristic on a project's own settings key that the Agent would honour, where the Agent holds no session history for that project, or where the project sits under a temporary directory or Downloads. Trust is what makes a project layer load, and CVE-2025-59536 is what happens when it loads before anyone meant it to; the Check Point and PromptArmor write-ups on both Agents describe a trust record appearing for a path the user never opened. The Agent's own bookkeeping is the sharpest signal available: a project that is trusted and has never been worked in was trusted by something other than a person sitting in it. A folder under temp or Downloads is worth the same line however much history it has, because that is where a clone lands before anyone has looked at it. The trust record itself is never an Item, since its key is an absolute path no content hash can carry between machines, so the Heuristic sits on what the trust made live. It fires only where a Surface Adapter stated whether the Agent holds session history for the project: an entry nobody stated that for is a fact nobody read, not a project nobody worked in. Weight 2 and a context Heuristic: a project opened for the first time reads exactly like this, which is why it is never a verdict on its own."
    references  = "https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/ https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    settings.trust_stated
    and item.kind == "SettingsEntry"
    and item.scope == "project"
    and item.activation == "active"
    and item.registered
    and (
      not settings.trust_has_sessions
      or item.project_root matches /^(\/private)?\/(tmp|var\/folders)\//
      or item.project_root contains "/Downloads/"
    )
}
