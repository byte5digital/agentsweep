rule as_0550_raw_ip_endpoint {
  meta:
    id          = 550
    title       = "A public address written out as numbers instead of a name"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file reaches a machine on the internet by its number, which is how a server with no name and no owner is reached."
    description = "A public IPv4 literal standing where a hostname belongs: the host of an http or https URL, or the argument of a transfer, shell or lookup command. Numbers skip the registration, the certificate and the reputation a name carries, which is why the poisoned skill campaigns fetched their payload from one. Loopback and the private ranges (10, 127, 169.254, 172.16 to 172.31, 192.168, 0.0.0.0) are subtracted, so a local development server and a machine on the office network stay silent; a version number inside a path stays silent too, because the literal has to sit at a host position. A private and a public address on the same line count against each other, so the pattern is deliberately quiet about a line carrying both."
    references  = "https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html https://safedep.io/malicious-npm-packages-claude-code-hooks/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $ip_url         = /https?:\/\/(\d{1,3}\.){3}\d{1,3}([:\/?#"'\s]|$)/
    $ip_url_private = /https?:\/\/(10\.|127\.|0\.0\.0\.0|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/
    $ip_cmd         = /\b(nc|ncat|netcat|socat|ssh|scp|sftp|rsync|telnet|ftp|curl|wget|ping|dig|nslookup)\s([^\n]{0,60}[\s@]|[^\n]{0,58}:\/\/)?(\d{1,3}\.){3}\d{1,3}([\s:\/"']|$)/
    $ip_cmd_private = /\b(nc|ncat|netcat|socat|ssh|scp|sftp|rsync|telnet|ftp|curl|wget|ping|dig|nslookup)\s([^\n]{0,60}[\s@]|[^\n]{0,58}:\/\/)?(10\.|127\.|0\.0\.0\.0|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/

  condition:
    #ip_url > #ip_url_private or #ip_cmd > #ip_cmd_private
}
