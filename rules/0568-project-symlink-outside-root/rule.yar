rule as_0568_project_symlink_outside_root {
  meta:
    id          = 568
    title       = "A project file that is really a link to somewhere else on disk"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 2
    kinds       = "InstructionFile,Skill,SettingsEntry"
    status      = "stable"
    plain       = "What looks like a file in this project is a link to a file outside it, so what the agent reads is not what the project shows."
    description = "A Project Scope Item whose entry on the Surface is a symbolic link resolving outside the project root. Reviewing the repository says nothing about what the agent will read: the link is one line in git and the content it points at is not, so it can be replaced at any time by anything that can write to that other path, and a clone keeps the link. Claude Code treats a symlinked rule target outside the working directory as an external import for its approval dialog, which is the same worry from the other side. A link that stays inside the project root stays silent, and so does a link in the user's own configuration, where pointing a rules folder at a synced directory is ordinary."
    references  = "https://code.claude.com/docs/en/memory docs/research/claude-code-surfaces.md docs/research/attack-catalogue.md#5"
    sensitive   = false

  condition:
    item.scope == "project"
    and item.is_symlink
    and item.link_target != ""
    and item.project_root != ""
    and not (item.link_target startswith item.project_root)
}
