rule as_0504_html_comment_instruction_language {
  meta:
    id          = 504
    title       = "An HTML comment that talks to the agent"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin"
    status      = "stable"
    reviewer_directed = true
    plain       = "A comment in this file speaks to the agent, and a person reading the rendered page never sees it."
    description = "An HTML comment whose text names an agent, gives it a standing order, or names a command to run. Rendered markdown hides the comment and the model reads it, so a note meant for a human and a note meant for the agent look the same on disk and are not. A comment that carries an actual role or priority tag is rule 0004's and is excluded here, as is any file that carries such a tag; editor pragmas, licence headers and to-do notes carry none of this language."
    references  = "https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_readme_instruction_injection_ai_coding_agents_20260317-csa-styled.pdf"
    sensitive   = false

  strings:
    $role_tag     = /<\/?(system|user_query|user|assistant|human|IMPORTANT|hidden|instructions?|priority)\b[^>]{0,80}>/ nocase
    $c_agent      = /<!--([^-]|-[^-]){0,2000}\b(assistant|the agent|the model|claude|codex|copilot|language model|ai assistant)\b/ nocase
    $c_directive  = /<!--([^-]|-[^-]){0,2000}\b(you must|you should|you will|always (run|use|include|add|append|send)|never (tell|mention|show|log|report)|do not (tell|mention|show|reveal|ask|report)|ignore the|disregard the)\b/ nocase
    $c_command    = /<!--([^-]|-[^-]){0,2000}\b(curl|wget|npm install|pip install|chmod|base64 -d|eval)\b/ nocase

  condition:
    item.file_type == "text" and not $role_tag and any of ($c_*)
}
