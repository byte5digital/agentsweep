rule as_0561_user_helper_with_network {
  meta:
    id          = 561
    title       = "A helper command in the user's own settings that talks to the network"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 3
    kinds       = "SettingsEntry"
    status      = "stable"
    plain       = "A small command in your own settings runs again and again while you work, and this one contacts a server every time."
    description = "One of the settings keys that run a command of their own (statusLine, fileSuggestion, apiKeyHelper, otelHeadersHelper, awsAuthRefresh, awsCredentialExport, gcpAuthRefresh) in User Scope, with a transfer command or a plain http address in its value. These keys run before the workspace is trusted, run repeatedly, and receive session context, which is what makes a quiet channel out of one. A third-party installer that writes one is the documented worry; no campaign has been published, so this stays a Heuristic. The same keys committed in a repository are rules 0006 and 0505's. A helper that runs a local script or reads the Keychain stays silent."
    references  = "https://www.sonarsource.com/blog/claude-arbitrary-code-execution/ https://code.claude.com/docs/en/settings-reference docs/research/attack-catalogue.md#5"
    sensitive   = true

  condition:
    item.kind == "SettingsEntry"
    and item.scope == "user"
    and settings.key_path matches /^((statusLine|fileSuggestion)\.command|apiKeyHelper|otelHeadersHelper|awsAuthRefresh|awsCredentialExport|gcpAuthRefresh)$/
    and settings.value matches /\b(curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|https?:\/\//
}
