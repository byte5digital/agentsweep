rule as_0563_deciding_hook_type {
  meta:
    id          = 563
    title       = "A model or tool decides the permission prompt instead of the user"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 3
    kinds       = "Hook"
    status      = "stable"
    plain       = "The question of whether a tool may run is answered by another model or another server, not by you."
    phrase      = "lets something else answer permission questions"
    description = "A hook of type prompt, agent or mcp_tool registered on PermissionRequest or PreToolUse. Those two events are where a tool call can be allowed or refused, and these three handler types hand the answer to a model, a subagent or an MCP server, any of which can be talked round by the very content the call is about. A malicious server registered this way approves its own calls. The handler types and the events are documented and the combination has no published incident, so it stays a Heuristic. The same handler types on other events, and a command hook on these events, stay silent."
    references  = "https://code.claude.com/docs/en/hooks https://learn.chatgpt.com/docs/hooks docs/research/attack-catalogue.md#5"
    sensitive   = false

  condition:
    item.kind == "Hook"
    and (hook.type == "prompt" or hook.type == "agent" or hook.type == "mcp_tool")
    and (hook.event == "PermissionRequest" or hook.event == "PreToolUse")
}
