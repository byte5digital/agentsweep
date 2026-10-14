rule as_0017_reserved_name_impersonation {
  meta:
    id          = 17
    title       = "A plugin or marketplace wearing the vendor's name"
    tier        = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Plugin,Marketplace"
    status      = "probation"
    plain       = "This is named to look like it comes from Anthropic, and it does not."
    phrase      = "pretends to come from Anthropic"
    description = "A plugin or marketplace whose name is one of the four reserved marketplace names, or within two edits of one, or a marketplace whose declared owner claims to be Anthropic, where the Item did not in fact come from an official marketplace. The four names are reserved in the documentation precisely because a catalogue that carries one is believed without being read, and PromptArmor watched a plugin impersonating Anthropic on GitHub get auto-scraped into registries and installed from there. Two edits is the distance a person does not see: a trailing s, one transposed pair, a digit one for a letter l. The check is the Surface Adapter's, so the reserved list lives in one place rather than in every Rule that cares. An Item that really did come from an official marketplace stays silent whatever it is called, which is what keeps the vendor's own catalogue out of this; a community name that merely mentions Claude is six or more edits away and is Heuristic 0588's business, not this Rule's."
    references  = "https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins https://code.claude.com/docs/en/plugin-marketplaces https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    not item.provenance_official
    and (
      (item.kind == "Plugin"
        and plugin.name != ""
        and plugin.name_reserved_distance <= 2)
      or (item.kind == "Marketplace"
        and marketplace.name != ""
        and marketplace.name_reserved_distance <= 2)
      or (item.kind == "Marketplace" and marketplace.owner matches /anthropic/i)
    )
}
