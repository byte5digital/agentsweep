rule as_0588_vendor_word_in_a_non_official_name {
  meta:
    id          = 588
    title       = "A name that borrows the vendor's, from a source that is not the vendor's"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,Plugin,Marketplace"
    status      = "stable"
    plain       = "This is called Anthropic, Claude or official, and it did not come from Anthropic."
    description = "A skill, plugin or marketplace whose name carries the word anthropic, claude or official, on an Item that did not come from an official marketplace. The documentation asks skill authors to keep anthropic and claude out of a name for exactly this reason: the name is the only thing most people read before installing, and PromptArmor's injected plugin got installed because it looked like the vendor's. It is not a Rule because the community names itself this way constantly and always has; a name near a reserved name is the unambiguous case and that is Rule 0017. Weight 2: a borrowed word is worth a line beside whatever else fired, and never a verdict on its own. Anything from an official marketplace stays silent, whatever it is called."
    references  = "https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    not item.provenance_official
    and (
      (item.kind == "Skill" and skill.name matches /anthropic|claude|official/i)
      or (item.kind == "Plugin" and plugin.name matches /anthropic|claude|official/i)
      or (item.kind == "Marketplace" and marketplace.name matches /anthropic|claude|official/i)
    )
}
