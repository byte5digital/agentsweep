rule as_0506_hosted_proxy_base_url {
  meta:
    id          = 506
    title       = "The agent's API traffic pointed at a third party"
    tier        = 2
    category    = "exposure"
    severity    = "medium"
    class       = 6
    kinds       = "EnvFile,SettingsEntry"
    status      = "stable"
    plain       = "Your prompts and replies go through someone else's server before they reach the vendor."
    phrase      = "sends your prompts through someone else's server"
    description = "A base URL key set to a host that is neither the vendor's nor this machine, in an untracked env file or in settings the user owns. Gateways and proxies are ordinary company infrastructure, so this is an Exposure and never a Threat: it says only that everything typed into the agent is readable at that hop, and that a key sent with it is readable there too. A local model server on loopback and the vendor's own host are not matched, and the same key committed in the repository is rule 0007's."
    references  = "https://github.com/advisories/GHSA-jh7p-qr78-84p7 docs/research/claude-code-surfaces.md"
    sensitive   = true

  strings:
    $env_any    = /\b(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_VERTEX_BASE_URL)[ \t]*=[ \t]*["']?https?:\/\/[A-Za-z0-9._\[\]:-]{1,80}/
    $env_local  = /\b(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_VERTEX_BASE_URL)[ \t]*=[ \t]*["']?https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])[:\/]/
    $env_vendor = /\b(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_VERTEX_BASE_URL)[ \t]*=[ \t]*["']?https?:\/\/(api\.anthropic\.com|api\.openai\.com)[\/"'\s]/

  condition:
    item.provenance != "repository" and (
      (item.kind == "EnvFile" and #env_any > #env_local + #env_vendor)
      or (item.kind == "SettingsEntry"
          and settings.key_path matches /(^|\.)(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_VERTEX_BASE_URL)$/
          and settings.value_host != ""
          and not (settings.value_host matches /^(api\.anthropic\.com|api\.openai\.com|127\.0\.0\.1|localhost|0\.0\.0\.0|::1)$/))
    )
}
