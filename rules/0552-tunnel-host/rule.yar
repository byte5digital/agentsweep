rule as_0552_tunnel_host {
  meta:
    id          = 552
    title       = "A tunnel service that puts a laptop on the public internet"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file names a tunnel service, which gives a machine a public address for a few hours and leaves nothing behind."
    phrase      = "names a tunnel service"
    description = "A host belonging to one of the tunnel services that hand out a throwaway public name pointing at whatever is listening on the other end: ngrok, Cloudflare quick tunnels, localtunnel, serveo, localhost.run, pinggy and bore. A payload server or a collector run this way needs no domain, no certificate and no hosting, and the name is gone by the time anyone looks. Developers also use them to show work in progress, which is why this is a Heuristic; the list lives in the rule rather than in an Indicator List because these service names do not rot. Cloudflare's and ngrok's own company domains are not on the list."
    references  = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $t01 = "ngrok.io" nocase fullword
    $t02 = "ngrok.app" nocase fullword
    $t03 = "ngrok-free.app" nocase fullword
    $t04 = "ngrok.dev" nocase fullword
    $t05 = "trycloudflare.com" nocase fullword
    $t06 = "loca.lt" nocase fullword
    $t07 = "serveo.net" nocase fullword
    $t08 = "localhost.run" nocase fullword
    $t09 = "lhr.life" nocase fullword
    $t10 = "pinggy.io" nocase fullword
    $t11 = "pinggy.link" nocase fullword
    $t12 = "bore.pub" nocase fullword
    $t13 = "tunnelmole.net" nocase fullword

  condition:
    any of them
}
