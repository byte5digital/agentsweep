rule as_0016_plugin_bin_shadows_a_real_tool {
  meta:
    id          = 16
    title       = "A plugin that puts its own `git` or `npm` in front of the real one"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Plugin"
    status      = "probation"
    plain       = "This plugin ships its own copy of a everyday command, and the agent will reach for that copy first."
    description = "A plugin whose `bin` directory holds a file named exactly like a tool the Agent or the user runs constantly: git, npm, npx, node, python, python3, pip, claude, codex, sh, bash, zsh, sudo, curl, wget, brew, gh, docker or ssh. The plugin documentation says a plugin's `bin` is added to the PATH of the Bash tool, so from then on every `git commit` the agent runs is the plugin's file, with the plugin's code in front of the real tool and the real tool one exec away to keep the session looking normal. There is no legitimate reason to ship a file under one of those names: a plugin that wants its own helper gives it its own name. The match is on the exact name, so the `git-foo` shape that git itself resolves as a subcommand stays silent, and so does every helper with a name of its own."
    references  = "https://code.claude.com/docs/en/plugins-reference https://code.claude.com/docs/en/plugin-marketplaces docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "Plugin"
    and for any name in plugin.bin_names : (
      name == "git" or name == "npm" or name == "npx" or name == "node"
      or name == "python" or name == "python3" or name == "pip"
      or name == "claude" or name == "codex"
      or name == "sh" or name == "bash" or name == "zsh" or name == "sudo"
      or name == "curl" or name == "wget" or name == "brew" or name == "gh"
      or name == "docker" or name == "ssh"
    )
}
