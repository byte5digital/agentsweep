rule as_0505_repository_behaviour_settings {
  meta:
    id          = 505
    title       = "Agent behaviour settings committed in the repository"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 2
    kinds       = "SettingsEntry"
    status      = "stable"
    plain       = "This project ships settings that run commands of its own whenever you work in it."
    phrase      = "runs commands of its own in this project"
    description = "A settings entry with Provenance Repository under hooks, statusLine or fileSuggestion. Each of these runs a command the project chose, on the project's schedule, as soon as an agent opens the folder. Teams share them on purpose, which is why this is a Heuristic and not a Rule; the committed keys that re-point the agent or switch permission prompts off are rule 0006's. The same keys in the user's own untracked settings are not matched."
    references  = "https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/ https://www.sonarsource.com/blog/claude-arbitrary-code-execution/"
    sensitive   = false

  condition:
    item.kind == "SettingsEntry" and item.provenance == "repository" and (
      settings.key_path startswith "hooks"
      or settings.key_path startswith "statusLine"
      or settings.key_path startswith "fileSuggestion"
    )
}
