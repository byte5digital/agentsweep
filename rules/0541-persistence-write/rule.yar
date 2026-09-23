rule as_0541_persistence_write {
  meta:
    id          = 541
    title       = "A write to a place the machine reads on every login"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Plugin,Hook,InstructionFile,Subagent,McpServer"
    status      = "stable"
    plain       = "This item installs something that starts again on its own, long after the task it came for is done."
    description = "A launch agent or launch daemon path, a launchctl load, a crontab written rather than listed, an append to a shell startup file, or a write into /etc. Every one of them outlives the session, which is what an implant needs and what a skill, a hook or an MCP server has no reason to want; the npm packages SafeDep found did exactly this so the payload came back on every session. Reading these places stays silent: listing the cron table, grepping a startup file for an alias, and reading /etc/hosts all name the same paths without changing them."
    references  = "https://safedep.io/malicious-npm-packages-claude-code-hooks/ https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    $launch_agent  = /Library\/Launch(Agents|Daemons)\//
    $launchctl     = /\blaunchctl[ \t]+(load|bootstrap|enable|submit|start)\b/
    $crontab_write = /\bcrontab[ \t]+-(e|r)\b|\|[ \t]*crontab\b|\/etc\/cron\.(d|daily|hourly)\//
    $rc_redirect   = /(>>?|\btee[ \t]+(-a[ \t]+)?|\bsed[ \t]+-i[^\n]{0,40})[ \t]*["']?(~|\$HOME|\/Users\/[^\s\/"']{1,32})?\/?\.(bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin|profile|kshrc)\b/
    $rc_open       = /\bopen\s*\(\s*[^\n]{0,80}\.(bashrc|bash_profile|zshrc|zprofile|zshenv|profile)['"]\s*\)?\s*,\s*['"][aw]/
    $etc_write     = /(>>?|\btee[ \t]+(-a[ \t]+)?|\bsed[ \t]+-i[^\n]{0,40}|\binstall[ \t]+-[^\n]{0,40})[ \t]*["']?\/etc\/[A-Za-z0-9._\/-]{1,60}/

  condition:
    item.file_type == "text" and any of them
}
