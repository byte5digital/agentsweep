rule as_0582_unknown_origin_user_surface {
  meta:
    id          = 582
    title       = "A hook or MCP server in the user's own configuration with no known origin"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "critical"
    class       = 3
    kinds       = "Hook,McpServer"
    status      = "stable"
    plain       = "Nothing on this machine can say where this entry came from, and it runs a command whenever the agent starts."
    description = "A context Heuristic on Provenance: a User Scope hook or MCP server that no marketplace, plugin, repository or agent write accounts for, and that AgentSweep cannot see having been placed by hand either. That is the shape a dependency implant leaves behind, a postinstall script appending one entry to a configuration nobody reads twice. It is also the shape of an entry the user typed themselves before AgentSweep existed, which is why the weight is 1 and the sentence says only that the origin is unaccounted for. An entry the adapter can attribute stays silent, and so does the same entry in a project, where the repository stands behind it and rules 0006 and 0505 apply."
    references  = "https://safedep.io/malicious-npm-packages-claude-code-hooks/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.scope == "user"
    and item.provenance == "unknown"
    and (item.kind == "Hook" or item.kind == "McpServer")
}
