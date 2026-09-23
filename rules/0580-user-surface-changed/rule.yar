rule as_0580_user_surface_changed {
  meta:
    id          = 580
    title       = "The user's own executable configuration changed or appeared since the Baseline"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 5
    kinds       = "Hook,McpServer,SettingsEntry,Plugin"
    status      = "stable"
    plain       = "Something that runs on your machine when the agent starts is not what it was the last time AgentSweep looked."
    description = "A context Heuristic: it reads item.baseline and item.scope and matches no bytes at all. A hook, an MCP server, a settings entry or a plugin in the user's own configuration whose content differs from the hash AgentSweep last accepted, or that appeared after the Surface was already covered. These four kinds are where a swap costs an attacker nothing and buys a command on the next launch, which is the MCPoison shape: approve a harmless server, replace its command afterwards. Content the user acknowledged, trusted, or that AgentSweep wrote itself reads unchanged before Rules run, and an Item first seen before its Surface was covered reads none, so neither is matched. Weight 2 is the cap for a Heuristic that decides on context alone: a change is a reason to read the Item, never a verdict on it. The standalone question of whether the change was the user's own is the core's, not this Heuristic's. Every other kind and scope is 0581."
    references  = "https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.scope == "user"
    and (item.baseline == "changed" or item.baseline == "added")
    and (item.kind == "Hook" or item.kind == "McpServer"
         or item.kind == "SettingsEntry" or item.kind == "Plugin")
}
