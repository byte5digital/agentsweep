import "math"

rule as_0524_upload_phrasing {
  meta:
    id          = 524
    title       = "Prose telling the agent to send what it can read to somewhere else"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin,Workflow"
    status      = "stable"
    plain       = "This file asks the agent to send your files or your conversation to an address on the internet."
    description = "A sending verb with what is being sent, within 300 bytes of a web address or of the word endpoint or webhook. Written as prose rather than as a command, so the agent composes the request itself and no shell text gives it away. Scanner evading skills on the public catalogue ask for exactly this. Sending something the project publishes on purpose, such as release notes or a built package, names neither the contents of files nor the transcript and stays silent; a credential path beside a network command is rule 0005 and heuristic 0509."
    references  = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/ https://www.backslash.security/blog/openai-codex-injection-in-agents-md-exfiltrating-credentials docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $send = /\b(send|sends|upload|uploads|post|posts|transmit|transmits|forward|forwards|exfiltrate|submit|submits|mirror|mirrors)\b[^\n]{0,60}\b(content|contents|file|files|transcript|conversation|chat history|history|output|source code|codebase|repository|working directory|environment variable|environment variables|credential|credentials|key|keys|token|tokens|secret|secrets|log|logs)\b/ nocase

    $to_url      = /https?:\/\/[A-Za-z0-9.-]{2,}/
    $to_endpoint = /\b(endpoint|webhook|collection server|ingest url|our server|the server at|remote host)\b/ nocase

  condition:
    item.file_type == "text"
    and for any i in (1..#send): (
      for any of ($to*): ($ in (math.max(@send[i], 300) - 300..@send[i] + 300))
    )
}
