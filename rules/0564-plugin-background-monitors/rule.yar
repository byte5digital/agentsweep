rule as_0564_plugin_background_monitors {
  meta:
    id          = 564
    title       = "A plugin that keeps a process running in the background"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Plugin"
    status      = "stable"
    plain       = "This plugin keeps a program of its own running while you work, and what it says is fed back to the agent."
    phrase      = "keeps a program running in the background"
    description = "A plugin whose manifest declares monitors. A monitor is a command the agent starts in the background and leaves running, and whatever it writes is injected as a notification, so one plugin gets both a resident process and a channel into the conversation without a tool call. The capability is documented and no abuse is published, so this is weight 1: it says only that the plugin asked for more than a plugin usually needs, and is worth reading beside whatever else fired on the same tree."
    references  = "https://code.claude.com/docs/en/plugins-reference docs/research/claude-code-surfaces.md docs/research/attack-catalogue.md#5"
    sensitive   = false

  condition:
    item.kind == "Plugin" and plugin.has_monitors
}
