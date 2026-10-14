rule as_0565_path_scoped_rule_file {
  meta:
    id          = 565
    title       = "A rule file that waits for the deployment, CI or secret files to be opened"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 2
    kinds       = "InstructionFile"
    status      = "stable"
    plain       = "This file holds instructions that stay out of sight until the agent opens your build, deployment or secret files."
    phrase      = "hides instructions until secret files are opened"
    description = "A rule file whose paths frontmatter scopes it to continuous integration definitions, deployment and infrastructure files, or env, key and credential files. A path-scoped rule is loaded only when the agent reads a file the glob matches, so it is absent from the startup context and from a context listing, and it speaks exactly when the agent is holding the most dangerous file in the repository. Teams scope rules to those same paths for honest reasons, which is why this is weight 1 and says only where the instructions wake up, never what they say. A rule scoped to ordinary source, and prose about a deployment pipeline in a file with no paths frontmatter, both stay silent."
    references  = "https://code.claude.com/docs/en/memory docs/research/claude-code-surfaces.md docs/research/attack-catalogue.md#5"
    sensitive   = false

  strings:
    $ci     = /(^|\n)paths:[\s\S]{0,200}(\.github\/workflows|\.gitlab-ci|Jenkinsfile|\.circleci|azure-pipelines|bitbucket-pipelines|\.buildkite|\.drone)/ nocase
    $deploy = /(^|\n)paths:[\s\S]{0,200}(deploy|Dockerfile|docker-compose|terraform|\.tf["'\s,\]]|helm|k8s|kubernetes|ansible|fastlane|Procfile)/ nocase
    $secret = /(^|\n)paths:[\s\S]{0,200}(\.env|secret|credential|\.pem|\.p12|id_rsa|id_ed25519|\.npmrc|\.netrc|vault)/ nocase

  condition:
    item.kind == "InstructionFile" and any of them
}
