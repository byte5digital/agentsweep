rule as_0521_secrecy_phrasing {
  meta:
    id          = 521
    title       = "Text that tells the agent to keep what it does from the user"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin,Workflow,Hook"
    status      = "stable"
    reviewer_directed = true
    plain       = "This file asks the agent to do something without telling you about it."
    phrase      = "tells the agent to keep secrets from you"
    description = "An order not to tell, mention or report a step to the user, an instruction to act silently or without asking, or a request to hide a command or its output. The malicious skills Mandiant found and the SANDWORM_MODE packages both carry this sentence beside the step they want unseen, because the user is the last control left once the agent has decided to act. Telling the user what changed, or asking before a destructive step, is the opposite and stays silent. Reviewer directed, because the sentence also asks whatever reads the file afterwards to say nothing."
    references  = "https://cloud.google.com/blog/products/identity-security/beyond-source-code-the-files-ai-coding-agents-trust-and-attackers-exploit https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $do_not_tell   = /\b(do not|don't|never|no need to)\b[^\n]{0,30}\b(tell|inform|notify|mention|show|reveal|disclose|report|surface|display|announce)\b[^\n]{0,40}\b(the user|the human|the operator|the owner|anyone|this step|this command|these steps|what you did)\b/ nocase
    $secretly      = /\b(silently|covertly|discreetly|without telling|without informing|without notifying|without alerting)\b[^\n]{0,60}\b(run|runs|execute|executes|install|installs|download|downloads|fetch|send|sends|upload|uploads|copy|copies|read|reads|write|writes|add|adds|append|appends|delete|deletes)\b/ nocase
    $act_secretly  = /\b(run|runs|execute|executes|install|installs|download|downloads|fetch|send|sends|upload|uploads|copy|copies|append|appends)\b[^\n]{0,60}\b(silently|covertly|discreetly|without telling|without informing|without notifying|without alerting)\b/ nocase
    $no_permission = /\b(do not|don't|never|without)\b[^\n]{0,20}\bask(ing)?\b[^\n]{0,40}\b(permission|confirmation|approval|the user|the human|the owner)\b/ nocase
    $hide_it       = /\b(hide|conceal|suppress|omit)\b[^\n]{0,60}\bfrom[ \t]{1,4}(the user|the human|the operator|the owner|the summary|your summary|the output|the log|the logs)\b/ nocase

  condition:
    item.file_type == "text" and any of them
}
