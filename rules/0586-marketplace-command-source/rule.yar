rule as_0586_marketplace_command_source {
  meta:
    id          = 586
    title       = "A marketplace that runs a command to fetch a plugin"
    tier        = 2
    weight      = 3
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Marketplace"
    status      = "stable"
    plain       = "This catalogue runs a program of its own every session to decide what to install."
    phrase      = "runs a program to decide what to install"
    description = "A marketplace listing one of its plugins with a `command` source. The documentation describes it as an enterprise distribution mechanism and says plainly that a marketplace can execute arbitrary code on the machine with the user's privileges: the command runs each session to produce the plugin, so whoever can edit the catalogue has a shell, and the plugin the command prints never passes through a repository anybody watches. It stays out of the Rule tier because the mechanism is documented and supported, which fails the second precision point, and it carries weight 3 because outside a company that chose it there is almost no reason to meet one. What the command actually does, when it pipes a fetch into a shell, is already Rule 0001 through the Marketplace kind."
    references  = "https://code.claude.com/docs/en/plugin-marketplaces https://code.claude.com/docs/en/plugins-reference docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "Marketplace"
    and for any entry in marketplace.entries : ( entry.source_kind == "command" )
}
