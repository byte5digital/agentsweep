import "math"

rule as_0593_remote_instructions {
  meta:
    id          = 593
    title       = "Text telling the Agent to fetch remote content and follow the instructions in it"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin"
    status      = "stable"
    plain       = "This file tells the agent to take its orders from a page on the internet."
    description = "A fetch of remote content and an order to follow the instructions, the steps or the directives in it, within 400 bytes of each other. Content that arrives this way can be changed after any review, which is what the scanner-evading skills on the public catalogue used, so the file under scan never has to carry the payload at all. Fetching a page in order to read, summarise or quote it stays silent, and so does an order to follow a runbook that lives in the repository. Not reviewer_directed: the text addresses the Agent, not a reviewer."
    references  = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/ https://securitylabs.datadoghq.com/articles/malicious-skills-supply-chain-risks-in-coding-agents-with-dynamic-context/"
    sensitive   = false

  strings:
    $fetch               = /\b(fetch|download|retrieve|curl|wget|request)\b[\s\S]{0,80}(https?:\/\/|\bURL\b|\bendpoint\b)/ nocase
    $follow_instructions = /\b(follow|obey|carry out|execute|perform|apply|comply with)\b[\s\S]{0,30}\b(instructions|steps|directives|commands)\b/ nocase

  condition:
    item.file_type == "text"
    and for any i in (1..#fetch): (
      for any of ($follow*): ($ in (math.max(@fetch[i], 400) - 400..@fetch[i] + 400))
    )
}
