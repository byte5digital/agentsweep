rule as_0551_non_standard_port {
  meta:
    id          = 551
    title       = "A web address on a port the web does not use"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file talks to a machine on the internet on an unusual port, which is what a listener put up for one job looks like."
    description = "An http or https URL carrying an explicit port that is neither 80 nor 443, on a host that is not this machine and not the private network. A collector stood up for one campaign listens wherever it is convenient, and the port is the cheapest thing about it. Ports 80 and 443 are subtracted, and so is every loopback or private host, because a development server on 3000 or 5173 is how the day is spent. Weight 1: plenty of honest services run on 8443 or 9000, so this only means something beside whatever else fired on the same Item."
    references  = "https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $port     = /\bhttps?:\/\/[A-Za-z0-9._-]{1,80}:\d{2,5}\b/
    $standard = /\bhttps?:\/\/[A-Za-z0-9._-]{1,80}:(80|443)\b/
    $loopback = /\bhttps?:\/\/(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[A-Za-z0-9._-]{0,60}:\d{2,5}\b/

  condition:
    #port > #standard + #loopback
}
