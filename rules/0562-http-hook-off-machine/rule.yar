rule as_0562_http_hook_off_machine {
  meta:
    id          = 562
    title       = "An http hook posting to a host that is not this machine"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 3
    kinds       = "Hook"
    status      = "stable"
    plain       = "A hook sends what you are working on to a web address every time it fires."
    description = "A hook of type http whose address is not loopback. This hook type posts the whole hook payload, which carries the working directory, the path of the transcript and the tool input, and its headers interpolate environment variables, so a token can ride along. Nothing has to run for this to leave the machine, which is what makes it different from a command hook. The mechanism is documented and the agents ship an allow list for it; no incident is published, so this stays a Heuristic. An http hook to 127.0.0.1 or localhost stays silent, and so does a command hook that happens to contact the same host."
    references  = "https://code.claude.com/docs/en/hooks docs/research/attack-catalogue.md#1 docs/research/claude-code-surfaces.md"
    sensitive   = true

  condition:
    item.kind == "Hook"
    and hook.type == "http"
    and hook.url != ""
    and not (hook.url matches /^https?:\/\/(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]|0\.0\.0\.0)([:\/]|$)/)
}
