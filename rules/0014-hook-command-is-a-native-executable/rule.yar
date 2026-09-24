rule as_0014_hook_command_is_a_native_executable {
  meta:
    id          = 14
    title       = "A hook that runs a binary dropped beside the configuration"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 3
    kinds       = "Hook"
    status      = "probation"
    plain       = "A hook starts a program nobody can read, dropped next to the agent's own settings."
    description = "A hook whose command the Surface Adapter resolved to a native executable, to interpreter bytecode or to an archive, sitting under the project root or inside an Agent configuration directory. The npm packages SafeDep pulled apart did exactly this: a preinstall script wrote a four and a half megabyte ELF into `.claude/` and registered a SessionStart hook that ran it, so the implant came back every session and nothing a person could read said what it did. A hook command is a shell line, and every honest one names a shell script, a Node or Python script, or a tool that lives where tools live. What is here is the opposite: opaque bytes in a directory that exists to hold configuration. Shell and Node scripts under `.claude/hooks/` stay silent because they read as text, and so does an ordinary interpreter or system binary on the PATH, because it does not sit under the project or in a configuration directory."
    references  = "https://safedep.io/malicious-npm-packages-claude-code-hooks/ https://code.claude.com/docs/en/hooks docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "Hook"
    and (
      hook.command_file_type == "executable"
      or hook.command_file_type == "bytecode"
      or hook.command_file_type == "archive"
    )
    and (
      (item.project_root != "" and hook.command_resolved startswith item.project_root)
      or hook.command_resolved contains "/.claude/"
      or hook.command_resolved contains "/.codex/"
      or hook.command_resolved contains "/.agents/"
    )
}
