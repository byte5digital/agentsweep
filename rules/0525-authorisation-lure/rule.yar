rule as_0525_authorisation_lure {
  meta:
    id          = 525
    title       = "Text claiming the step ahead is already approved or already safe"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin"
    status      = "stable"
    reviewer_directed = true
    plain       = "This file claims someone already agreed to what it is about to do."
    phrase      = "claims it is already approved"
    description = "A claim that the user, the owner or the team has already approved what follows and that nothing more need be asked, that the steps below are pre-approved, that this is only a test, or that the file itself is safe and should be reported as such. The claim is unverifiable by construction and is aimed at whoever decides next, the agent or the person reading its summary. Recording a real approval in prose, such as a maintainer signing off a design in an issue, names what was approved and not what to skip, and stays silent. Reviewer directed: this is the wording written to talk a reviewer, a scanner or a judging model round, so a benign verdict on an item carrying it counts as unsure."
    references  = "https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/ https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $already_approved = /\b(the user|the owner|the operator|the administrator|the admin|the maintainer|the team|the customer)\b[^\n]{0,40}\b(has|have|already)\b[^\n]{0,30}\b(approved|authorised|authorized|consented|agreed|signed off|given permission|given consent)\b[^\n]{0,80}\b(so|therefore|no need|does not need|do not need|don't need|without asking|proceed|go ahead)\b/ nocase
    $pre_approved     = /\b(this|these|the following|the steps below|the commands below|the command below)\b[^\n]{0,40}\b(is|are|has been|have been)\b[^\n]{0,30}\b(pre-approved|pre approved|preapproved|already approved|already authorised|already authorized|pre-authorised|pre-authorized|vetted|cleared|whitelisted|allow-listed|allowlisted)\b/ nocase
    $only_a_test      = /\b(this is only a test|this is just a test|this is a test run|this is a drill|this is a simulation|for testing purposes only|this is a sandboxed environment, so|this is a sandbox, so)\b/ nocase
    $declare_safe     = /\b(this|the) (file|skill|plugin|script|command|step|content) is (completely |entirely |perfectly |known to be )?(safe|trusted|harmless|benign|verified)[ \t]{0,4}[.,;!]/ nocase
    $report_safe      = /\b(report|mark|classify|treat|consider|record)\b[^\n]{0,30}\b(this|it|the file|the skill|the plugin|the content)\b[^\n]{0,30}\b(as )?(safe|benign|clean|harmless|approved|trusted)\b/ nocase

  condition:
    item.file_type == "text" and any of them
}
