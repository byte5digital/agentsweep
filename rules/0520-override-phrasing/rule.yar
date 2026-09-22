rule as_0520_override_phrasing {
  meta:
    id          = 520
    title       = "Text that tells the agent to drop the instructions it already has"
    tier        = 2
    weight      = 3
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin,Workflow"
    status      = "stable"
    reviewer_directed = true
    plain       = "This file tells the agent to throw away the instructions it was given and take new ones from here."
    description = "An order to ignore, forget or override what came before, a claim that the text supersedes the instructions already in force, a new identity handed to the reader, or a mode said to be engaged. Prompt injection lives on these sentences: the file is read as instructions, so one line of it can put the rest of the session under the file's author. Telling the agent to ignore a build directory, or saying it is now ready for the next step, carries none of this. Reviewer directed, because whatever model is later asked whether the file is safe reads the same sentence."
    references  = "https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $ignore_previous = /\b(ignore|disregard|forget|discard|override)\b[^\n]{0,40}\b(previous|prior|earlier|preceding|above|foregoing|system)\b[^\n]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines|context)\b/ nocase
    $supersedes      = /\b(supersede|supersedes|superseded|replace|replaces|override|overrides|takes precedence over|take precedence over)\b[^\n]{0,40}\b(previous|prior|earlier|any other|all other|the system|the user)\b[^\n]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|guideline|guidelines)\b/ nocase
    $you_are_now     = /\byou are now\b[^\n]{0,40}\b(an|a|the)\b[^\n]{0,30}\b(assistant|agent|ai|model|system|administrator|admin|root|operator|unrestricted|uncensored|unfiltered)\b/ nocase
    $mode_engaged    = /\b(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b[^\n]{0,30}\b(enabled|engaged|activated|active|on)\b/ nocase
    $in_mode         = /\b(you are|the assistant is|the agent is|the model is)[ \t]+(now[ \t]+)?in[ \t]+(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b/ nocase

  condition:
    item.file_type == "text" and any of them
}
