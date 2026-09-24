rule as_0584_any_dynamic_context {
  meta:
    id          = 584
    title       = "A skill that runs a command while it is being loaded"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill"
    status      = "stable"
    plain       = "This skill runs a command of its own while it is being read, before anyone sees it."
    description = "A skill or command file that carries a dynamic-context block: an inline span opened with an exclamation mark and a backtick, or a fenced block opened the same way. Claude Code runs those during preprocessing, before the body ever reaches the model and without waiting for workspace trust, which is what Datadog's work on dynamic context is about. Rule 0012 is the half of this with no legitimate reading, a block that fetches or reads a credential. What is left is the half the documentation encourages: a date, a branch name, a `git status`. So this is weight 1 and nothing on its own. It says that this skill executes at load time at all, which is worth knowing under whatever else fired on the same tree."
    references  = "https://securitylabs.datadoghq.com/articles/malicious-skills-supply-chain-risks-in-coding-agents-with-dynamic-context/ https://code.claude.com/docs/en/skills docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "Skill" and skill.has_dynamic_context
}
