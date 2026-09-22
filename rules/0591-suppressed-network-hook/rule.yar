rule as_0591_suppressed_network_hook {
  meta:
    id          = 591
    title       = "Command hook with a network call and its output suppressed"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Hook"
    status      = "stable"
    plain       = "A hook contacts a server every time it runs and hides what it did from the transcript."
    description = "A command hook entry that declares suppressOutput true while its command reaches the network (curl, wget, nc, ncat, netcat, socat, scp, sftp, an Invoke-WebRequest, or a plain http URL). The pairing is what the injected-marketplace-plugin incident used to keep the beacon out of the transcript; either half alone is ordinary, a quiet formatter as much as a visible build ping."
    references  = "https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins https://code.claude.com/docs/en/hooks"
    sensitive   = false

  strings:
    $suppress = /"suppressOutput"\s*:\s*true/

  condition:
    $suppress and hook.type == "command" and (
      hook.command matches /\b(curl|wget|nc|ncat|netcat|socat|scp|sftp|Invoke-WebRequest|Invoke-RestMethod)\b/
      or hook.command matches /https?:\/\//
    )
}
