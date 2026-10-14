// GENERATED from iocs/ips.txt by the pack build. Do not edit by hand.
rule as_0901_ioc_ips {
  meta:
    id          = 901
    title       = "Known command-and-control address"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Workflow,ExecPolicy,Generic"
    status      = "probation"
    plain       = "This file contacts a machine that attackers are known to control."
    phrase      = "contacts a machine attackers control"
    description = "Exact addresses taken from published incident reports (iocs/ips.txt). An address that only contains an entry, such as one digit longer, is not a whole word and stays silent. Regenerated on every pack build."
    references  = "docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $i0 = "91.92.242.30" fullword
    $i1 = "2.26.75.16" fullword
    $i2 = "45.115.38.27" fullword
    $i3 = "207.90.194.2" fullword

  condition:
    any of them
}
