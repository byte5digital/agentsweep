rule as_0594_plugin_server_outside_the_plugin_root {
  meta:
    id          = 594
    title       = "A plugin's MCP server started from outside the plugin"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "McpServer"
    status      = "stable"
    plain       = "This plugin starts a background server that does not live inside the plugin."
    phrase      = "starts a server from outside the plugin"
    description = "An MCP server declared in a plugin's own `.mcp.json` whose command the Surface Adapter resolved to a path outside that plugin's directory. The plugin documentation writes such a command as a path under the plugin root, and a plugin's servers start on their own when the plugin is enabled, so a command that points somewhere else starts something the plugin does not ship and a plugin update does not change. The legitimate reading is ordinary enough to keep this at weight 1: a plugin that wraps a tool the user already installed points at that tool on purpose, and many do. It is a line of context under whatever else fired on the same plugin, not a verdict."
    references  = "https://code.claude.com/docs/en/plugins-reference docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "McpServer"
    and item.provenance == "plugin"
    and mcp.command_resolved != ""
    and mcp.command_outside_root
}
