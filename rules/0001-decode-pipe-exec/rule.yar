rule as_0001_decode_pipe_exec {
  meta:
    id          = 1
    title       = "Decode-and-execute or download-and-execute chain"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace"
    status      = "probation"
    plain       = "This file contains a command that downloads or unpacks hidden code and runs it straight away."
    phrase      = "downloads and runs hidden code"
    description = "Shell text that pipes base64-decoded or downloaded content directly into a shell or interpreter, downloads to /tmp and executes in the same statement, or unpacks a password-protected archive and makes the result executable or runs it in the same statement. Seen in ClawHavoc, ToxicSkills, the skills.sh typosquat campaign and CurXecute. No legitimate skill, hook, MCP launch command, marketplace entry or instruction file needs to execute content it has just decoded, fetched or unpacked; unpacking an archive and then reading a file out of it stays silent. Marketplace is one of the kinds, so a marketplace command source that pipes a fetch into a shell is caught here. Inside a skill, plugin or marketplace tree the rule reads only what an Agent loads as instructions or runs: SKILL.md and the files it points to, commands, agent definitions, hooks and their scripts. A README, a licence, a changelog or a contributing guide is a document for a human reader (item.file_is_document) and stays silent, because a plugin README that documents installing a runtime with curl piped into bash is ordinary documentation and never reaches the Agent as an instruction."
    references  = "https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/ https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ https://labs.zenity.io/post/attackers-target-agents-via-the-skill-supply-chain https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison"
    sensitive   = false

  strings:
    // base64 -d ... | sh   (also -D on macOS and --decode)
    $decode_pipe_shell  = /base64\s+(-d|-D|--decode)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
    // base64 -d ... | node / python / perl
    $decode_pipe_interp = /base64\s+(-d|-D|--decode)[^\n|]{0,200}\|\s*(sudo\s+)?(node|python3?|perl|ruby)\b/
    // eval $(echo ... | base64 -d) and eval "$(... base64 --decode)"
    $eval_decode        = /eval\s+["']?\$\(\s*(echo|printf)[^)]{0,300}base64\s+(-d|-D|--decode)/
    // curl/wget ... | sh
    $fetch_pipe_shell   = /\b(curl|wget)\s[^\n|]{0,300}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
    // curl/wget ... | node / python / perl
    $fetch_pipe_interp  = /\b(curl|wget)\s[^\n|]{0,300}\|\s*(sudo\s+)?(node|python3?|perl|ruby)\b/
    // curl ... > /tmp/x && node /tmp/x   (download to temp then execute in the same statement)
    $fetch_tmp_exec     = /\b(curl|wget)\s[^\n]{0,300}(>|-o|-O)\s*\/(tmp|var\/tmp)\/[^\s;&|]{1,100}[^\n]{0,100}(&&|;)\s*(sudo\s+)?(node|python3?|perl|ruby|sh|bash|zsh|chmod\s+\+x)\b/
    // unzip -P <password> ... && chmod +x / sh / node   (password-protected extraction then execution)
    $unzip_exec         = /\bunzip\s+-P\s[^\n]{0,200}(&&|;|\|)\s*(sudo\s+)?(chmod\s+\+x|(ba|z|da)?sh|node|python3?|perl|ruby)\b/
    // Invoke-WebRequest / iwr piped into Invoke-Expression
    $iwr_iex            = /\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n|]{0,300}\|\s*(Invoke-Expression|iex)\b/ nocase

  condition:
    // Only what an Agent loads as instructions: a README, a licence or a
    // changelog inside a tree is written for a human reader.
    any of them and not item.file_is_document
}
