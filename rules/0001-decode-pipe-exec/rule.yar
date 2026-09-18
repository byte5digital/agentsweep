rule as_0001_decode_pipe_exec {
  meta:
    id          = 1
    title       = "Decode-and-execute or download-and-execute chain"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent"
    status      = "probation"
    plain       = "This file contains a command that downloads or unpacks hidden code and runs it straight away."
    description = "Shell text that pipes base64-decoded or downloaded content directly into a shell or interpreter, or downloads to /tmp and executes in the same statement. Seen in ClawHavoc, ToxicSkills, the skills.sh typosquat campaign and CurXecute. No legitimate skill, hook, MCP launch command or instruction file needs to execute content it has just decoded or fetched."
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
    // Invoke-WebRequest / iwr piped into Invoke-Expression
    $iwr_iex            = /\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n|]{0,300}\|\s*(Invoke-Expression|iex)\b/ nocase

  condition:
    any of them
}
