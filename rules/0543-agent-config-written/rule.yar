rule as_0543_agent_config_written {
  meta:
    id          = 543
    title       = "A skill or instruction file that writes the agent's own configuration"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 3
    kinds       = "Skill,Plugin,InstructionFile,Subagent"
    status      = "stable"
    plain       = "This item changes the agent's own settings or its standing instructions, which outlast the task."
    description = "A redirect, tee, sed, jq or move whose target is one of the Agent's own files, a write call on one of them, or prose telling the agent to add a line to them: the settings files, ~/.claude.json, the Codex config, and the user's own memory and rule files. What the item asks for once becomes what the Agent does from then on, which is how a permission nobody granted and an instruction nobody wrote get in. Reading the settings to report them stays silent, so does keeping notes in the project's own documents, and a hook that writes the settings is rule 0013."
    references  = "https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    $redirect = /(>>?|\btee[ \t]+(-a[ \t]+)?|\bsed[ \t]+-i[^\n]{0,40})[ \t]*["']?[^\n"';|&]{0,60}(\.claude\/settings(\.local)?\.json|\.claude\.json|\.codex\/config\.toml|\.codex\/hooks\.json|\.claude\/CLAUDE\.md|\.codex\/AGENTS\.md|\.claude\/rules\/)/
    $move     = /\b(mv|cp|install)[ \t]+[^\n;|&]{0,80}(\.claude\/settings(\.local)?\.json|\.claude\.json|\.codex\/config\.toml|\.claude\/CLAUDE\.md|\.codex\/AGENTS\.md)\b[ \t]*($|[\n;&|])/
    $write_call = /(\bopen\s*\(|\bfs\.(writeFile|writeFileSync|appendFile|appendFileSync)\s*\(|\bwrite_text\s*\(|\bFile\.write\s*\()[^\n]{0,100}(\.claude\/settings(\.local)?\.json|\.claude\.json|\.codex\/config\.toml|\.claude\/CLAUDE\.md|\.codex\/AGENTS\.md|\.claude\/rules\/)/
    $prose    = /\b(write|writes|append|appends|add|adds|insert|inserts|put|save|saves|store|stores|register|registers|record|records)\b[^\n]{0,60}(~\/\.claude\/|~\/\.codex\/|\.claude\/settings(\.local)?\.json|\.claude\.json|\.codex\/config\.toml|\.claude\/CLAUDE\.md|\.codex\/AGENTS\.md|\.claude\/rules\/)/ nocase

  condition:
    item.file_type == "text" and any of them
}
