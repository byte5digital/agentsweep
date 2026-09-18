rule as_0008_mcp_command_from_untrusted_location {
  meta:
    id          = 8
    title       = "MCP server launched from a temporary, unknown hidden or world-writable location, or a known-vulnerable package"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "McpServer"
    status      = "probation"
    plain       = "An MCP server is set to start from a folder where real tools are never installed, or uses a version of a package with a known remote code execution bug."
    description = "A stdio MCP server whose resolved command lives under a temp directory or ~/Downloads, under a hidden home directory that is not a known tool manager (SANDWORM wrote ~/.dev-utils), or in a world-writable location; or a pinned mcp-remote below 0.1.16 (CVE-2025-6514); or a pinned @modelcontextprotocol/server-filesystem below 2025.7.1 rooted at / or the home directory (CVE-2025-53109/53110). Unpinned packages are an Exposure, not this rule. Known-bad package names live in the IOC list rule."
    references  = "https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/ https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/"
    sensitive   = false

  condition:
    item.kind == "McpServer" and mcp.transport == "stdio" and (
      mcp.command_in_temp or mcp.command_in_downloads or mcp.command_world_writable or mcp.command_in_unknown_hidden_home
      or (mcp.package == "mcp-remote" and mcp.package_version matches /^0\.(0\.[0-9]+|1\.([0-9]|1[0-5]))$/)
      or (mcp.package == "@modelcontextprotocol/server-filesystem"
        and mcp.package_version matches /^(0\.|2025\.([1-6]\.|7\.0))/
        and for any a in mcp.args: (a == "/" or a == "$HOME" or a == "~" or a == item.project_root))
    )
}
