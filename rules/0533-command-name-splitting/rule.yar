import "math"

rule as_0533_command_name_splitting {
  meta:
    id          = 533
    title       = "A command name broken up so it cannot be read or searched for"
    tier        = 2
    weight      = 3
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Plugin,Hook,McpServer,Subagent,InstructionFile"
    status      = "stable"
    plain       = "A command here is written in pieces, so the name of what runs never appears in the file."
    phrase      = "writes a command in pieces"
    description = "A word split by an empty or one-fragment quote pair, a name glued together from three or more quoted pieces beside an exec call, a shell word carrying a hex escape for a letter, the field separator written as a brace expansion inside a command, or an indirect variable expansion. Every one of them reconstructs a command at run time while the file itself never contains the name, which defeats a reader and a string search alike. Setting the field separator in the ordinary way, and joining a web address to a variable, look nothing like this and stay silent."
    references  = "https://labs.zenity.io/post/attackers-target-agents-via-the-skill-supply-chain https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    // c""url and cu''rl, with the quotes escaped when the Item is an entry
    $empty_quotes  = /[A-Za-z][A-Za-z0-9_-]{0,10}(\\?"\\?"|'')[A-Za-z][A-Za-z0-9_-]{0,10}/
    // cu"r"l and c'ur'l
    $quoted_middle = /\b[a-z]{1,6}(\\?"[a-z]{1,4}\\?"|'[a-z]{1,4}')[a-z]{1,8}\b/
    // "cu" + "r" + "l" handed to something that runs it
    $concat        = /(["'][A-Za-z0-9_\/.-]{1,8}["']\s*[+.]\s*){2,}["'][A-Za-z0-9_\/.-]{1,8}["']/
    // $'\x63url', a shell word with a letter written as a hex escape
    $ansi_c_hex    = /\$'[^'\n]{0,40}\\{1,2}x[4-7][0-9A-Fa-f][^'\n]{0,40}'/
    // ${IFS} and cat$IFS/etc/hostname, the separator used as glue
    $ifs           = /\$\{IFS\}|[A-Za-z0-9_\/.-]\$IFS[A-Za-z0-9_\/.-]/
    // ${!name}, one more level of indirection before the command exists
    $indirect      = /\$\{![A-Za-z_][A-Za-z0-9_]{0,40}\}/

    $exec_shell = /\b(bash|zsh|\/bin\/sh|sh[ \t]+-c)\b/
    $exec_call  = /\b(eval|exec|execSync|execFile|execFileSync|spawn|spawnSync|Function|popen|system|subprocess|child_process|os\.system)\b/

  condition:
    item.file_type == "text" and (
      $empty_quotes or $quoted_middle or $ansi_c_hex or $ifs or $indirect
      or for any i in (1..#concat): (
        for any of ($exec*): ($ in (math.max(@concat[i], 200) - 200..@concat[i] + 200))
      )
    )
}
