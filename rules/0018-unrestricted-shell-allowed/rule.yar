rule as_0018_unrestricted_shell_allowed {
  meta:
    id          = 18
    title       = "Unrestricted shell or fetcher allowed without asking"
    tier        = 1
    category    = "exposure"
    severity    = "medium"
    class       = 6
    kinds       = "SettingsEntry,ExecPolicy"
    status      = "probation"
    plain       = "Your agent may run whole classes of commands, such as any shell command or any download, without asking you first."
    description = "A permissions.allow entry that grants a whole command class rather than one command: bare Bash, Bash(*), or Bash on a shell, a fetcher or an interpreter with nothing but a wildcard after it; or a Codex prefix_rule with decision allow whose pattern starts with a shell or a fetcher, or with an interpreter run with -c or -e. Both Agents append to these lists on every 'always allow', so the entry is usually the user's own and the Item never carries Drift. Exposure: never quarantined, offered the RemoveEntry fix action, which takes out this one entry and leaves the rest of the list alone. An allow entry scoped to a command or an endpoint (Bash(npm run test:*), Bash(curl https://host/path)) stays silent, and so does a prefix_rule that names a shell in order to prompt for it or forbid it."
    references  = "https://github.com/anthropics/claude-code/security/advisories/GHSA-mmgp-wc2j-qcv7 https://code.claude.com/docs/en/permissions https://learn.chatgpt.com/docs/agent-configuration/rules"
    sensitive   = false

  strings:
    // prefix_rule(pattern=["bash", "-lc"], decision="allow") and its kin
    $ep_shell       = /prefix_rule\s*\(\s*pattern\s*=\s*\[\s*"(sh|bash|zsh|ksh|dash|curl|wget)"[^\]]{0,200}\][^)]{0,300}decision\s*=\s*"allow"/
    // prefix_rule(pattern=["python3", "-c"], decision="allow") and its kin
    $ep_interpreter = /prefix_rule\s*\(\s*pattern\s*=\s*\[\s*"(python[0-9.]*|node|perl|ruby|osascript)"\s*,\s*"-[a-zA-Z]{0,2}[ce]"[^\]]{0,200}\][^)]{0,300}decision\s*=\s*"allow"/

  condition:
    (item.kind == "SettingsEntry"
      and settings.key_path startswith "permissions.allow"
      and (settings.value matches /^Bash$/
        or settings.value matches /^Bash\(\s*\*\s*\)$/
        or settings.value matches /^Bash\(\s*(sh|bash|zsh|ksh|dash|curl|wget|python[0-9.]*|node|eval)\s*:?\s*\*?\s*\)$/))
    or (item.kind == "ExecPolicy" and any of ($ep_*))
}
