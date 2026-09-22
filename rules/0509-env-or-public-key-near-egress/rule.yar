import "math"

rule as_0509_env_or_public_key_near_egress {
  meta:
    id          = 509
    title       = "An env file or a public key named beside a network command"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 4
    kinds       = "InstructionFile,Skill,Hook,Subagent,Plugin"
    status      = "stable"
    plain       = "This file names your local settings file or a key file right next to a way of sending it somewhere."
    description = "A .env path or a .pub key file within 300 bytes of a network transfer or lookup command. Both are excluded from rule 0005 because setup documentation mentions them honestly: registering a public key with a git host, or copying .env.example into place. Read together with the command beside them they still say the shape of an exfiltration, which is what the Heuristic tier is for. Private credential stores next to the same commands are rule 0005's."
    references  = "https://www.backslash.security/blog/openai-codex-injection-in-agents-md-exfiltrating-credentials docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $path_env = /\.env(\.(local|production|prod|development|dev|staging|test))?\b/
    $path_pub = /\.ssh\/[A-Za-z0-9_.-]{1,40}\.pub\b|\bid_(rsa|dsa|ecdsa|ed25519)\.pub\b/
    $egress   = /[\n`$(|;&\s](curl|wget|nc|ncat|netcat|scp|rsync|sftp|ping|nslookup|dig|whois|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+[-\w.\/$"'{]/

  condition:
    item.file_type == "text"
    and for any i in (1..#egress): (
      for any of ($path_*): ($ in (math.max(@egress[i], 300) - 300..@egress[i] + 300))
    )
}
