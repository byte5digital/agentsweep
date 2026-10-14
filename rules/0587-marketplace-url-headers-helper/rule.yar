rule as_0587_marketplace_url_headers_helper {
  meta:
    id          = 587
    title       = "A marketplace that runs a command to build its request headers"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Marketplace"
    status      = "stable"
    plain       = "This catalogue runs a program of its own to get the credentials it fetches with."
    phrase      = "runs a program to get its credentials"
    description = "A marketplace entry fetched from a URL that declares a headers helper. The helper is a shell command the Agent runs to produce the headers of the request, so a catalogue that declares one holds both a command that executes and a credential worth reading, and the plugin documentation lists it beside the `command` source as a payload surface. The legitimate use is the reason this is not a Rule: a private catalogue behind an authenticating proxy needs exactly this, and that is how the feature is documented. Weight 2, because a helper on a public catalogue has nothing to authenticate to."
    references  = "https://code.claude.com/docs/en/plugin-marketplaces https://code.claude.com/docs/en/plugins-reference docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "Marketplace"
    and for any entry in marketplace.entries : (
      entry.source_kind == "url" and entry.has_headers_helper
    )
}
