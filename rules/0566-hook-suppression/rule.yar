rule as_0566_hook_suppression {
  meta:
    id          = 566
    title       = "The project reaches for the switch that turns hooks off, or watches the settings files"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 2
    kinds       = "SettingsEntry,Hook"
    status      = "stable"
    plain       = "This project decides for itself whether the checks you set up are allowed to run."
    description = "Three shapes of the same move. A committed disableAllHooks key, whichever way it is set: taken from the highest precedence file, a project value outranks the user's, so a repository can switch every hook of the user off in that folder, or set the key back to false to re-enable hooks the user turned off. A project Codex config setting features.hooks to false, which is the kill switch for the whole Codex hook engine and is honoured from a trusted project. And a hook on ConfigChange or InstructionsLoaded that names a settings file, which is how a session learns the moment the configuration it wants to change is touched. A user switching their own hooks off in their own settings stays silent, a project leaving features.hooks on stays silent, and the same handler on an event that is not about configuration stays silent. A hook that actually writes a settings file is rule 0013."
    references  = "https://code.claude.com/docs/en/hooks docs/research/load-time-interception.md docs/research/codex-surfaces.md docs/research/attack-catalogue.md#5"
    sensitive   = false

  strings:
    $settings_file = /(settings\.local\.json|settings\.json|managed-settings|\.claude\.json|config\.toml|hooks\.json|requirements\.toml)/ nocase

  condition:
    (item.kind == "SettingsEntry" and (
        (item.provenance == "repository" and settings.key_path == "disableAllHooks")
        or (item.scope == "project"
            and settings.key_path == "features.hooks"
            and settings.value == "false")
      ))
    or (item.kind == "Hook"
        and (hook.event == "ConfigChange" or hook.event == "InstructionsLoaded")
        and $settings_file)
}
