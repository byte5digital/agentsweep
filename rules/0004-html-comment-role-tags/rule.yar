rule as_0004_html_comment_role_tags {
  meta:
    id          = 4
    title       = "Role or priority tag hidden inside an HTML comment"
    tier        = 1
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin"
    status      = "probation"
    plain       = "This file hides instructions to the agent inside a comment that people do not see when the file is rendered."
    description = "An HTML comment in markdown that contains a chat-role or priority tag such as <system>, <user_query>, <assistant>, <human>, <IMPORTANT>, <hidden> or <instructions>. Rendered markdown hides the comment; the model reads it. Claude Code strips block-level comments from CLAUDE.md, but the same file is read by Codex and other agents without stripping, and README or SECURITY files are read on demand. Comment text without such a tag is a T2 indicator."
    references  = "https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_readme_instruction_injection_ai_coding_agents_20260317-csa-styled.pdf"
    sensitive   = false

  strings:
    $comment_with_tag = /<!--([^-]|-[^-]){0,2000}<\/?(system|user_query|user|assistant|human|IMPORTANT|hidden|instructions?|priority)\b[^>]{0,80}>/ nocase

  condition:
    item.file_type == "text" and $comment_with_tag
}
