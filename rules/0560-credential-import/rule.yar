rule as_0560_credential_import {
  meta:
    id          = 560
    title       = "An instruction file that imports a credential file into the context"
    tier        = 2
    weight      = 3
    category    = "threat"
    severity    = "critical"
    class       = 4
    kinds       = "InstructionFile"
    status      = "stable"
    plain       = "This file pulls one of your key or password files into the conversation before anything is asked."
    description = "An at-sign import in an instruction file whose target is a credential store: a key under .ssh, the AWS, npm, PyPI, netrc, Docker, Kubernetes, GnuPG or GitHub CLI credentials, either agent's own stored login, or an env file. The import runs when the file is read, so the secret is in the context before a single instruction is judged, and any later sentence can send it on. The agents added an approval dialog for imports that leave the working directory, which shows the risk was seen; nothing published shows it being used, so this stays a Heuristic. A normal import of another document in the repository stays silent, and so does prose that merely names a credential path."
    references  = "https://code.claude.com/docs/en/memory https://www.backslash.security/blog/openai-codex-injection-in-agents-md-exfiltrating-credentials docs/research/attack-catalogue.md#5"
    sensitive   = true

  strings:
    $import_cred = /(^|[\s"'(])@[\w.~\/-]{0,64}(\.ssh\/[\w.-]{1,40}|\.aws\/(credentials|config)|\.netrc|\.npmrc|\.pypirc|\.kube\/config|\.docker\/config\.json|\.gnupg\/[\w.-]{1,40}|\.config\/gh\/hosts\.yml|\.claude\/\.credentials\.json|\.codex\/auth\.json)/
    $import_env  = /(^|[\s"'(])@[\w.~\/-]{0,64}\.env(\.[\w-]{1,20})?([\s"')]|$)/

  condition:
    item.kind == "InstructionFile" and any of them
}
