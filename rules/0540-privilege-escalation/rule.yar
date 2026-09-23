rule as_0540_privilege_escalation {
  meta:
    id          = 540
    title       = "A step that asks for administrator rights or opens a file to everyone"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,Plugin,InstructionFile,Subagent,Hook"
    status      = "stable"
    plain       = "A step here runs as the administrator, or opens a file up to every account on the machine."
    description = "A sudo call in front of a command or a path, a mode that grants everyone write access, or a setuid bit. An agent that is told to work through sudo is an agent whose mistakes and whose planted instructions both land as root, and a world-writable or setuid file is how a later step gets back in. Setting the executable bit on a script the item ships, and a mode that narrows access such as 600 or 755, are ordinary housekeeping and stay silent, as is prose that says no administrator rights are needed. Weight 1: plenty of honest installers ask for sudo, so this counts only in company."
    references  = "https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/ https://labs.reversec.com/posts/2026/05/skill-issues-compromising-claude-code-with-malicious-skills-agents-part-1 docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    $sudo_command = /\bsudo[ \t]+(-[A-Za-z]+[ \t]+)*(cp|mv|rm|mkdir|ln|tee|dd|chmod|chown|chgrp|install|launchctl|systemctl|defaults|spctl|csrutil|xattr|nvram|kextload|dscl|visudo|profiles|scutil|networksetup|pmset|softwareupdate|security|killall|curl|wget|npm|pnpm|yarn|pip3?|python3?|node|perl|ruby|bash|zsh|sh|make|apt|apt-get|yum|dnf|brew)\b/
    $sudo_path    = /\bsudo[ \t]+(-[A-Za-z]+[ \t]+)*[.~\/][A-Za-z0-9_.~\/-]{2,60}/
    $world_write  = /\bchmod\b[^\n]{0,24}\b(777|776|766|757|707|666|a\+rwx|o\+w|ugo\+rwx)\b/
    $setuid       = /\bchmod\b[^\n]{0,24}([ug]\+s\b|\+s\b|[24][0-7]{3}\b)/

  condition:
    item.file_type == "text" and any of them
}
