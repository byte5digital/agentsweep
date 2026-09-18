rule as_0010_secret_in_mcp_config {
  meta:
    id          = 10
    title       = "Plaintext secret in MCP server configuration"
    tier        = 1
    category    = "exposure"
    severity    = "medium"
    class       = 6
    kinds       = "McpServer"
    status      = "probation"
    plain       = "An MCP server entry contains a real password, token or key written out in full."
    description = "A well-formed credential in an MCP server entry: AWS access key id, GitHub token, Anthropic or OpenAI project key, Slack token, Google API key, PEM private key block, or a connection URL with an embedded password; a literal Authorization header; a token in the URL query; or an Anthropic environment variable forwarded into a remote server's headers or URL. Matches land on sensitive fields, so Findings show only a redacted form. Environment variable references such as ${GITHUB_TOKEN} are not matched. Exposure: never quarantined, offered a fix action instead."
    references  = "https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/ https://www.trendaisecurity.com/en-us/resources-insights/deep-research/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud"
    sensitive   = true

  strings:
    $key_aws           = /AKIA[0-9A-Z]{16}/
    $key_github        = /\bgh[pousr]_[A-Za-z0-9]{36,}/
    $key_github_pat    = /\bgithub_pat_[A-Za-z0-9_]{22,}/
    $key_anthropic     = /\bsk-ant-[A-Za-z0-9_\-]{20,}/
    $key_openai        = /\bsk-proj-[A-Za-z0-9_\-]{20,}/
    $key_slack         = /\bxox[bpas]-[0-9A-Za-z\-]{10,}/
    $key_google        = /\bAIza[0-9A-Za-z_\-]{35}/
    $key_pem           = /-----BEGIN [A-Z ]*PRIVATE KEY-----/
    $key_db_url        = /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqps?):\/\/[^:\/\s"]+:[^@\/\s"]{4,}@/
    $forward_anthropic = "${ANTHROPIC_"

  condition:
    item.kind == "McpServer" and (
      any of ($key_*)
      or mcp.has_literal_authorization
      or mcp.url matches /[?&](token|api_key|apikey|access_token|key)=/
      or (mcp.transport != "stdio" and $forward_anthropic)
    )
}
