// GENERATED from iocs/hosts.txt by the pack build. Do not edit by hand.
rule as_0900_ioc_hosts {
  meta:
    id          = 900
    title       = "Known malicious host"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "probation"
    plain       = "This file contacts a server that is known to distribute malware."
    description = "Exact host names taken from published incident reports (iocs/hosts.txt). Regenerated on every pack build."
    references  = "docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $h0 = "socifiapp.com" nocase fullword
    $h1 = "openclawcli.vercel.app" nocase fullword
    $h2 = "api.getpaperclipp.com" nocase fullword
    $h3 = "sentry.anyclaw.store" nocase fullword
    $h4 = "swarm.gadgethumans.com" nocase fullword
    $h5 = "angelic.su" nocase fullword
    $h6 = "pkg-metrics.official334.workers.dev" nocase fullword
    $h7 = "freefan.net" nocase fullword
    $h8 = "fanfree.net" nocase fullword

  condition:
    any of them
}
