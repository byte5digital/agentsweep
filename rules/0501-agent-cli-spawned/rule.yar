rule as_0501_agent_cli_spawned {
  meta:
    id          = 501
    title       = "An agent command line spawned from a script, hook or instruction"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Hook,Plugin,Subagent,InstructionFile"
    status      = "stable"
    plain       = "This file starts a coding agent on its own, with nobody watching what it does."
    description = "A non-interactive agent invocation: `claude -p` or `claude --print`, `codex exec`, or the `--full-auto` flag of either. An agent started this way reads whatever prompt the caller hands it and acts on it without a person in the loop, which turns one planted file into a second agent under the attacker's control. Continuous integration does this legitimately, which is why it is a Heuristic; the permission and sandbox bypass flags are rule 0002's."
    references  = "https://labs.reversec.com/posts/2026/05/skill-issues-compromising-claude-code-with-malicious-skills-agents-part-1 docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $claude_print = /\bclaude\b[^\n]{0,120}[ \t](-p|--print)\b/
    $codex_exec   = /\bcodex[ \t]+exec\b/
    $full_auto    = /--full-auto\b/

  condition:
    any of them
}
