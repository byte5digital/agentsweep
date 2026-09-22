rule as_0554_url_shortener {
  meta:
    id          = 554
    title       = "A shortened link, which hides where it goes"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file uses a shortened link, so neither you nor the agent can see where it actually leads."
    description = "A host from the public link shorteners. A short link tells a reviewer nothing about the destination, survives the review unchanged and can be re-pointed afterwards, which is why lures and droppers reach for one. People also paste short links out of habit, so this is a Heuristic. The boundary is the whole host: a name that merely ends in one of these, such as orbit.lyric.example.invalid, is not matched, and neither is prose about shortening links. The list lives in the rule because these service names do not rot."
    references  = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $s01 = "bit.ly" nocase fullword
    $s02 = "tinyurl.com" nocase fullword
    $s03 = "t.co" nocase fullword
    $s04 = "goo.gl" nocase fullword
    $s05 = "ow.ly" nocase fullword
    $s06 = "is.gd" nocase fullword
    $s07 = "buff.ly" nocase fullword
    $s08 = "rebrand.ly" nocase fullword
    $s09 = "cutt.ly" nocase fullword
    $s10 = "shorturl.at" nocase fullword
    $s11 = "rb.gy" nocase fullword
    $s12 = "tiny.cc" nocase fullword
    $s13 = "shrtco.de" nocase fullword
    $s14 = "short.io" nocase fullword
    $s15 = "v.gd" nocase fullword

  condition:
    any of them
}
