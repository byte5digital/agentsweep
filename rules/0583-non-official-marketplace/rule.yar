rule as_0583_non_official_marketplace {
  meta:
    id          = 583
    title       = "A plugin or skill installed from a marketplace nobody vouches for"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Plugin,Skill"
    status      = "stable"
    plain       = "This came from a catalogue that is not the vendor's, so nobody reviewed it before it reached your machine."
    phrase      = "came from a catalogue nobody vouches for"
    description = "A context Heuristic on Provenance: a plugin or skill whose Provenance is a marketplace, where that marketplace is not one of the official ones. A community catalogue is a git repository anyone may open, and the research on skill distribution found hundreds of listings with no review between the author and an install, so the one fact worth carrying is that nothing stood between them. Community catalogues are also how most useful plugins are shared, which is the whole reason this is weight 1 and not a Rule: it is a line of context under whatever else fired, never a Finding of its own. A plugin from an official marketplace stays silent, and so does a skill the user wrote or copied in by hand, which carries no marketplace at all."
    references  = "https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/ https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.provenance == "marketplace"
    and not item.provenance_official
    and (item.kind == "Plugin" or item.kind == "Skill")
}
