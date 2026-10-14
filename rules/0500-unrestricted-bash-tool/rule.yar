rule as_0500_unrestricted_bash_tool {
  meta:
    id          = 500
    title       = "Unrestricted Bash in a skill or subagent tool list"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,Subagent"
    status      = "stable"
    plain       = "This skill may run any shell command at all, instead of the few it needs."
    phrase      = "may run any shell command"
    description = "A skill or subagent whose tool list grants Bash with no argument pattern: `allowed-tools: Bash`, `Bash(*)`, or the same as a YAML list item, or the skill view reporting either. A scoped grant such as Bash(git status:*) stays silent, and so does a tool list without Bash. Very common in honest skills, which is why it is weight 1: on its own it says only that nothing narrows what this skill may run."
    references  = "https://labs.reversec.com/posts/2026/05/skill-issues-compromising-claude-code-with-malicious-skills-agents-part-1 docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $inline_bare = /(allowed-tools|allowed_tools|tools)[ \t]*:[^\n]{0,300}\bBash\b[ \t]*(,|\]|"|'|\r|\n)/
    $inline_star = /(allowed-tools|allowed_tools|tools)[ \t]*:[^\n]{0,300}\bBash\([ \t]*\*[ \t]*\)/
    $list_key    = /(allowed-tools|allowed_tools|tools)[ \t]*:[ \t]*\r?\n/
    $list_item   = /\n[ \t]*-[ \t]*Bash(\([ \t]*\*[ \t]*\))?[ \t]*\r?\n/

  condition:
    (item.kind == "Skill" or item.kind == "Subagent") and (
      $inline_bare or $inline_star
      or ($list_key in (0..1000) and $list_item in (0..1000))
      or (item.kind == "Skill" and for any t in skill.allowed_tools: (t == "Bash" or t == "Bash(*)"))
    )
}
