// GENERATED from iocs/packages.txt by the pack build. Do not edit by hand.
rule as_0902_ioc_packages {
  meta:
    id          = 902
    title       = "Known malicious package"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Workflow,ExecPolicy,Generic"
    status      = "probation"
    plain       = "This configuration installs a package that is known to be malicious."
    description = "Package names taken from published incident reports (iocs/packages.txt), matched as a whole word in the bytes under scan and against the package an MCP server entry installs. A longer name that merely starts with an entry is not a whole word and stays silent. Regenerated on every pack build."
    references  = "docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $p0 = "mcp-runcmd-server" fullword
    $p1 = "mcp-runcommand-server" fullword
    $p2 = "@lanyer640/mcp-runcommand-server" fullword
    $p3 = "postmark-mcp" fullword
    $p4 = "claud-code" fullword
    $p5 = "cloude-code" fullword
    $p6 = "suport-color" fullword
    $p7 = "opencraw" fullword

  condition:
    any of them
    or mcp.package == "mcp-runcmd-server"
    or mcp.package == "mcp-runcommand-server"
    or mcp.package == "@lanyer640/mcp-runcommand-server"
    or mcp.package == "postmark-mcp"
    or mcp.package == "claud-code"
    or mcp.package == "cloude-code"
    or mcp.package == "suport-color"
    or mcp.package == "opencraw"
}
