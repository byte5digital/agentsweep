rule as_0523_persona_framing {
  meta:
    id          = 523
    title       = "Text that hands the agent a persona with no rules"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin"
    status      = "stable"
    reviewer_directed = true
    plain       = "This file tries to give the agent a new character that is allowed to do anything."
    phrase      = "gives the agent a character with no rules"
    description = "Jailbreak framing: a persona described as unrestricted, uncensored or jailbroken, a claim that the reader is no longer bound by its guidelines, an order to ignore the safety rules, or an order to stay in character. Nine in ten of the malicious skills Snyk confirmed carried prompt injection of this shape, because a persona survives further turns in a way a single command does not. Giving a skill an ordinary role, such as a careful reviewer or a release manager, is how skills are written and stays silent. Reviewer directed, because the persona is offered to whatever model reads the file next."
    references  = "https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $jailbreak_persona = /\b(you are|act as|acts as|pretend to be|pretend you are|roleplay as|assume the role of|assume the persona of|from now on you are|from now on you will)\b[^\n]{0,40}\b(unrestricted|uncensored|unfiltered|unbound|jailbroken|amoral|rogue|lawless|dan\b|do anything now)\b/ nocase
    $no_restrictions   = /\b(no longer bound by|not bound by|free from|released from|exempt from|unbound by)\b[^\n]{0,30}\b(your|the|any|all)\b[^\n]{0,20}\b(restriction|restrictions|limitation|limitations|guideline|guidelines|rule|rules|policy|policies|safety|constraint|constraints)\b/ nocase
    $ignore_safety     = /\b(ignore|disregard|bypass|forget|drop|switch off|turn off)\b[^\n]{0,30}\b(your|the|any|all)\b[^\n]{0,20}\b(safety|ethics|ethical|alignment|guardrail|guardrails|content policy|content policies|refusal|refusals)\b/ nocase
    $in_character      = /\b(stay in character|remain in character|do not break character|never break character|do not leave this persona)\b/ nocase

  condition:
    item.file_type == "text" and any of them
}
