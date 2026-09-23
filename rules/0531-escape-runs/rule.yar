import "math"

rule as_0531_escape_runs {
  meta:
    id          = 531
    title       = "A command written as a run of character escapes"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Plugin,Hook,McpServer,Subagent"
    status      = "stable"
    plain       = "A command here is spelled out in escape codes, which hides what it actually runs."
    description = "Eight or more hex, unicode or percent escapes in a row within 300 bytes of a shell, an interpreter or an exec call. Written out, the run is an ordinary command; escaped, it passes a reader and every string search for the command's name, which is why the obfuscated skill and MCP samples carry it. A percent-encoded query inside a web address is how a search term travels and stays silent, and so does a run of escapes with no command anywhere near it, such as a table of box-drawing characters in documentation."
    references  = "https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ https://labs.zenity.io/post/attackers-target-agents-via-the-skill-supply-chain docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    // A backslash may arrive doubled, because an entry Item is scanned as JSON.
    $hex = /(\\{1,2}x[0-9A-Fa-f]{2}){8,}/
    $uni = /(\\{1,2}u[0-9A-Fa-f]{4}){8,}/
    $pct = /(%[0-9A-Fa-f]{2}){8,}/

    $url = /https?:\/\/[^\s"'`<>\\]{4,300}/ nocase

    $cmd_shell  = /\b(bash|zsh|\/bin\/sh|sh[ \t]+-c|sh['"]?,)\b/
    $cmd_interp = /\b(node|python3?|perl|ruby|osascript)\b/
    $cmd_eval   = /\b(eval|exec|execSync|execFile|spawn|spawnSync|system|popen|Function|printf)\b/
    $cmd_fetch  = /\b(curl|wget|nc|socat)\b/

  condition:
    item.file_type == "text" and (
      for any i in (1..#hex): (
        for any of ($cmd*): ($ in (math.max(@hex[i], 300) - 300..@hex[i] + 300))
      )
      or for any i in (1..#uni): (
        for any of ($cmd*): ($ in (math.max(@uni[i], 300) - 300..@uni[i] + 300))
      )
      or for any i in (1..#pct): (
        for any of ($cmd*): ($ in (math.max(@pct[i], 300) - 300..@pct[i] + 300))
        and not for any j in (1..#url): (
          @url[j] <= @pct[i] and @pct[i] < @url[j] + !url[j]
        )
      )
    )
}
