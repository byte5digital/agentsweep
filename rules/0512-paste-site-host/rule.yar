rule as_0512_paste_site_host {
  meta:
    id          = 512
    title       = "A paste site named in text an agent reads"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file names a paste site, which is where stolen text is usually sent and where payloads are usually kept."
    description = "A host from the paste and shell-paste services that campaigns reach for: anonymous, free, no account, and gone again within a day. Both halves of an attack use them, the payload on the way in and the stolen text on the way out. People also use them to share a log with a colleague, so this is a Heuristic; the list lives in the rule rather than in an Indicator List because these names do not rot."
    references  = "https://unit42.paloaltonetworks.com/malicious-payloads-hosted-on-paste-sites/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $p01 = "pastebin.com" nocase fullword
    $p02 = "paste.ee" nocase fullword
    $p03 = "hastebin.com" nocase fullword
    $p04 = "hasteb.in" nocase fullword
    $p05 = "ghostbin.com" nocase fullword
    $p06 = "rentry.co" nocase fullword
    $p07 = "rentry.org" nocase fullword
    $p08 = "dpaste.com" nocase fullword
    $p09 = "dpaste.org" nocase fullword
    $p10 = "privatebin.net" nocase fullword
    $p11 = "controlc.com" nocase fullword
    $p12 = "justpaste.it" nocase fullword
    $p13 = "0bin.net" nocase fullword
    $p14 = "termbin.com" nocase fullword
    $p15 = "sprunge.us" nocase fullword
    $p16 = "bpa.st" nocase fullword
    $p17 = "paste.rs" nocase fullword
    $p18 = "ix.io" nocase fullword

  condition:
    any of them
}
