rule as_0556_insecure_mcp_transport {
  meta:
    id          = 556
    title       = "An MCP server reached over a transport that protects nothing"
    tier        = 2
    category    = "exposure"
    severity    = "low"
    class       = 6
    kinds       = "McpServer"
    status      = "stable"
    plain       = "Everything this server sends and receives travels in the clear, where anyone on the network can read it."
    phrase      = "sends everything in the clear"
    description = "An MCP server on the deprecated server-sent-events transport, or on plain http to a host that is not this machine. Tool arguments carry file contents and tokens, so the whole conversation with the server is readable and changeable in transit. Streamable http over TLS replaces both. A server on loopback is not matched, because nothing leaves the machine. Hygiene rather than a finding about the file, so it is an Exposure and never quarantined."
    references  = "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.kind == "McpServer" and (
      mcp.transport == "sse"
      or (mcp.transport == "http" and mcp.url startswith "http://"
          and not (mcp.url matches /^http:\/\/(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)([:\/]|$)/))
    )
}
