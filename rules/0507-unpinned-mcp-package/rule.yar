rule as_0507_unpinned_mcp_package {
  meta:
    id          = 507
    title       = "An MCP server started from an unpinned package"
    tier        = 2
    category    = "exposure"
    severity    = "low"
    class       = 6
    kinds       = "McpServer"
    status      = "stable"
    plain       = "This server downloads whatever the latest version of a package happens to be, every time it starts."
    description = "An MCP server entry whose package carries no version, or whose launcher is told to install without asking (`npx -y` and its kin). Whoever can publish that package decides what runs on the machine on the next start, and a compromised release needs no access to anything here. Pinning the version, or installing the server once and naming the installed command, both silence this. Hygiene rather than a finding about the file, so it is an Exposure and never quarantined."
    references  = "https://www.wiz.io/blog/s1ngularity-supply-chain-attack docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "McpServer" and (
      (mcp.package != "" and mcp.package_version == "")
      or (mcp.command matches /(^|\/)(npx|bunx|pnpx|uvx)$/
          and for any a in mcp.args: (a == "-y" or a == "--yes"))
    )
}
