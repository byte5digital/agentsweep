rule as_0569_codex_notify_or_provider_auth {
  meta:
    id          = 569
    title       = "A Codex key in the user's own config that runs a command of its own"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 3
    kinds       = "SettingsEntry"
    status      = "stable"
    plain       = "Your own Codex settings start a program of their own, either after every turn or whenever a token is needed."
    phrase      = "starts a program of its own"
    description = "A User Scope Codex settings entry under notify or under a model provider's auth. The notify key is an argv that Codex runs after each turn with a JSON payload of what happened appended, and a provider's auth command is a subprocess run to fetch a token, so both are a command the user rarely remembers writing and a third party installer can add in one line. Codex strips both keys from a project config, which is why this is about the user's own file; the committed form is rule 0006. There is no published incident, so this stays a Heuristic, and it reads the key rather than the command: what the command does is every other Rule's ground. A provider's base URL or its env key stays silent, because neither starts a process."
    references  = "https://learn.chatgpt.com/docs/config-file/config-reference docs/research/codex-surfaces.md docs/research/attack-catalogue.md#5"
    sensitive   = true

  condition:
    item.kind == "SettingsEntry"
    and item.scope == "user"
    and item.agent == "codex"
    and settings.key_path matches /^(notify(\.[0-9]+)?|model_providers\.[^.]+\.auth(\.[A-Za-z0-9_.]+)?)$/
}
