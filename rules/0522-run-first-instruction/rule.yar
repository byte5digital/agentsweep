import "math"

rule as_0522_run_first_instruction {
  meta:
    id          = 522
    title       = "Text that puts a command before anything the user asked for"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "critical"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin"
    status      = "stable"
    plain       = "This file tells the agent to run a command before it does anything you asked for."
    description = "Run-first phrasing, such as before you do anything else, before every task or as your first step, within 300 bytes of a shell, fetch or package command. This is how the AGENTS.md credential theft Backslash published reached the machine: the command is attached to the start of every session rather than to a request, so it runs whatever the user came for. Run-first phrasing on its own is ordinary project wording, and a first step that reads a file or runs the project's own build tool is not a command in the list here, so both stay silent."
    references  = "https://www.backslash.security/blog/openai-codex-injection-in-agents-md-exfiltrating-credentials https://cloud.google.com/blog/products/identity-security/beyond-source-code-the-files-ai-coding-agents-trust-and-attackers-exploit docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $first = /\b(before you do anything|before doing anything|before anything else|before you start|before you begin|before you answer|before you respond|before you reply|before each task|before every task|before any task|before each request|before every request|before each session|before every session|as your first step|as the first step|as your first action|first,? you must|first,? always|always run|immediately run|run this first|run this before)\b/ nocase

    $cmd_curl   = /\bcurl\b/
    $cmd_wget   = /\bwget\b/
    $cmd_npx    = /\bnpx\b/
    $cmd_npm    = /\bnpm[ \t]+(install|run|exec)\b/
    $cmd_pip    = /\bpip3?[ \t]+install\b/
    $cmd_shell  = /\b(bash|zsh|\/bin\/sh|sh[ \t]+-c)\b/
    $cmd_interp = /\b(node|python3?|perl|ruby|osascript)\b/
    $cmd_base64 = /\bbase64\b/
    $cmd_chmod  = /\bchmod\b/
    $cmd_eval   = /\beval\b/
    $cmd_git    = /\bgit[ \t]+clone\b/

  condition:
    item.file_type == "text"
    and for any i in (1..#first): (
      for any of ($cmd*): ($ in (math.max(@first[i], 300) - 300..@first[i] + 300))
    )
}
