rule as_0542_protection_disabled {
  meta:
    id          = 542
    title       = "A step that switches a protection off before it acts"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,Plugin,InstructionFile,Subagent,Hook"
    status      = "stable"
    plain       = "A step here turns off one of the checks that would normally stand in its way."
    description = "A sandbox switched off on the command line, Gatekeeper assessment disabled, the quarantine attribute stripped from a downloaded file, system integrity protection touched, or prose telling the agent to skip the permission prompt. The protection is removed first and the interesting step comes after, which is the order that gives the shape away. Asking what a protection currently says stays silent, and so does listing the attributes on a download and leaving it to the user to allow it. The agent's own bypass flags are rule 0002's."
    references  = "https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/malicious-openclaw-skills-used-to-distribute-atomic-macos-stealer https://labs.reversec.com/posts/2026/05/skill-issues-compromising-claude-code-with-malicious-skills-agents-part-1 docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    $no_sandbox   = /--no-sandbox\b|--disable-sandbox\b|--sandbox[= ]none\b|--disable-setuid-sandbox\b/
    $spctl        = /\bspctl\b[^\n]{0,40}(--master-disable|--global-disable|--add\b|--remove\b)/
    $quarantine   = /\bxattr\b[^\n]{0,40}com\.apple\.quarantine|com\.apple\.quarantine[^\n]{0,40}\bxattr\b/
    $csrutil      = /\bcsrutil[ \t]+(disable|clear|authenticated-root[ \t]+disable)\b/
    $skip_prompt  = /\b(skip|skips|bypass|bypasses|suppress|suppresses|turn off|switch off|disable|get around|work around)\b[^\n]{0,30}\b(the[ \t]+|any[ \t]+|every[ \t]+)?(permission|approval|confirmation|consent|security|safety|sandbox)[ \t]*(prompt|prompts|dialog|dialogue|check|checks|question|questions|request|requests|warning|warnings)\b/ nocase

  condition:
    item.file_type == "text" and any of them
}
