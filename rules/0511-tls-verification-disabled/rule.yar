rule as_0511_tls_verification_disabled {
  meta:
    id          = 511
    title       = "Certificate checking switched off for a network call"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file fetches something over the network without checking who is answering."
    description = "`curl -k` or `curl --insecure`, `--no-check-certificate`, NODE_TLS_REJECT_UNAUTHORIZED set to zero, or GIT_SSL_NO_VERIFY switched on. Anyone on the path can then answer instead of the host that was asked, and whatever comes back is used as if it were genuine. Developers do this against staging hosts with self-signed certificates all the time, which is why it stays weight 1: it matters in the company of whatever else the same file does."
    references  = "https://docs.aws.amazon.com/whitepapers/latest/aws-vpc-connectivity-options/network-to-amazon-vpc-connectivity-options.html docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $curl_insecure = /\bcurl\b[^\n]{0,160}[ \t](-k|--insecure)\b/
    $no_check_cert = /--no-check-certificate\b/
    $node_tls      = /NODE_TLS_REJECT_UNAUTHORIZED[ \t]*[=:][ \t]*["']?0\b/
    $git_ssl       = /GIT_SSL_NO_VERIFY[ \t]*[=:][ \t]*["']?(1|true|yes)\b/

  condition:
    any of them
}
