rule as_0009_repository_metadata_execution {
  meta:
    id          = 9
    title       = "Git metadata that runs a command or escapes the repository before trust"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 2
    kinds       = "RepositoryMetadata"
    status      = "probation"
    plain       = "This project's git settings would run a hidden command as soon as an agent looks at the folder."
    description = "A .git/config core.fsmonitor set to anything but the built-in true/false (GitSpawn, CVE-2026-55607 and CVE-2026-19592), a core.hooksPath resolving outside the repository, a .git file (gitdir pointer) or worktree commondir resolving outside the standard worktree layout (CVE-2026-40068). Other exec-capable keys (sshCommand, pager, editor, filters, textconv, credential.helper, shell aliases), an in-repo hooksPath such as husky, and non-sample hook scripts are T2 indicators because pre-commit tooling installs them routinely. RepositoryMetadata is a never-auto kind, so this rule flags with a one-click fix that comments the key out."
    references  = "https://www.manifold.security/blog/ai-coding-agents-git-hijack https://security.snyk.io/vuln/SNYK-JS-ANTHROPICAICLAUDECODE-16301567"
    sensitive   = false

  condition:
    item.kind == "RepositoryMetadata" and (
      repo.gitdir_outside_repo or repo.commondir_outside_repo
      or for any k in repo.exec_keys: (
        (k.key == "core.fsmonitor" and not (k.value == "true" or k.value == "false" or k.value == ""))
        or (k.key == "core.hooksPath" and k.value_outside_repo)
      )
    )
}
