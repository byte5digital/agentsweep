rule as_0553_webhook_and_oast_host {
  meta:
    id          = 553
    title       = "An inbox that takes anything posted to it, no account needed"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file names a drop box that anyone can post to and only its owner can read, which is where taken data usually lands."
    phrase      = "names a drop box for taken data"
    description = "A catch-all webhook or out-of-band collector: webhook.site, a Discord or Slack incoming webhook path, the Telegram bot API, RequestBin and Pipedream, Beeceptor, and the interaction collectors interact.sh, oast and Burp Collaborator. Each gives an attacker a URL that accepts a POST from anywhere, costs nothing and needs no domain of their own, which is the whole back half of an exfiltration. Teams do post build results to a Slack or Discord webhook, so this is a Heuristic, and a message to a channel is not matched: only the incoming-webhook path is. The list lives in the rule because these service names do not rot."
    references  = "https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins https://cloud.google.com/blog/products/identity-security/beyond-source-code-the-files-ai-coding-agents-trust-and-attackers-exploit docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $w01 = "webhook.site" nocase fullword
    $w02 = "discord.com/api/webhooks" nocase
    $w03 = "discordapp.com/api/webhooks" nocase
    $w04 = "hooks.slack.com/services" nocase
    $w05 = "api.telegram.org/bot" nocase
    $w06 = "requestbin.com" nocase fullword
    $w07 = "requestbin.net" nocase fullword
    $w08 = "pipedream.net" nocase fullword
    $w09 = "beeceptor.com" nocase fullword
    $w10 = "interact.sh" nocase fullword
    $w11 = "oast.fun" nocase fullword
    $w12 = "oast.pro" nocase fullword
    $w13 = "oast.live" nocase fullword
    $w14 = "oast.site" nocase fullword
    $w15 = "oast.online" nocase fullword
    $w16 = "burpcollaborator.net" nocase fullword
    $w17 = "requestcatcher.com" nocase fullword

  condition:
    any of them
}
