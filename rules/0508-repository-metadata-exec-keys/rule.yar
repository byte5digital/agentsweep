rule as_0508_repository_metadata_exec_keys {
  meta:
    id          = 508
    title       = "Git metadata that can run a command when the agent reads the folder"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 2
    kinds       = "RepositoryMetadata"
    status      = "stable"
    plain       = "This folder's git settings can run a command of the project's choosing while the agent works in it."
    description = "A .git/config key that runs a command as an ordinary part of git's work: a hooksPath inside the repository, a clean or smudge filter process that is not git-lfs, a textconv for a diff driver, a credential helper or alias whose value starts with the shell escape, or core.sshCommand. Hook executables in .git/hooks count too. Pre-commit tooling installs several of these on purpose, which is why they are a Heuristic; the keys with no honest use, such as a non-builtin core.fsmonitor or a hooksPath that leaves the repository, are rule 0009's."
    references  = "https://www.manifold.security/blog/ai-coding-agents-git-hijack docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "RepositoryMetadata" and (
      repo.hook_executables_n > 0
      or for any k in repo.exec_keys: (
        (k.key == "core.hooksPath" and k.value != "" and not k.value_outside_repo)
        or (k.key matches /^filter\.[^.]+\.process$/ and not (k.key matches /^filter\.lfs\./))
        or k.key matches /^diff\.[^.]+\.textconv$/
        or k.key == "core.sshCommand"
        or (k.key matches /^credential(\.[^.]+)*\.helper$/ and k.value startswith "!")
        or (k.key matches /^alias\.[^.]+$/ and k.value startswith "!")
      )
    )
}
