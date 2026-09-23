rule as_0581_item_changed {
  meta:
    id          = 581
    title       = "An Item changed or appeared since the Baseline, outside the user's executable configuration"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 5
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file is not what it was the last time AgentSweep looked at it."
    description = "The other half of 0580, and a context Heuristic in the same way: it reads item.baseline and item.scope and matches no bytes. Content that differs from the hash AgentSweep last accepted, or that appeared after the Surface was covered, on everything 0580 does not take: the same four kinds outside User Scope, and every other kind in any scope. Weight 1, because a project file changing is what a working day looks like: a pull brings a new CLAUDE.md, a colleague adds a skill. It is worth one point only beside whatever else fired on the same Item. Acknowledged, trusted and AgentSweep's own content reads unchanged before Rules run, and an Item first seen before coverage reads none, so neither is matched. SettingsEntry is not among this Heuristic's kinds, so a settings entry outside User Scope is carried by whatever else fires on it."
    references  = "https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    (item.baseline == "changed" or item.baseline == "added")
    and not (item.scope == "user"
             and (item.kind == "Hook" or item.kind == "McpServer"
                  or item.kind == "SettingsEntry" or item.kind == "Plugin"))
}
