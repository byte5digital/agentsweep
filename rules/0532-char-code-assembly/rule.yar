import "math"

rule as_0532_char_code_assembly {
  meta:
    id          = 532
    title       = "A command assembled out of character codes"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Plugin,Hook,McpServer"
    status      = "stable"
    plain       = "This file builds a command out of numbers instead of writing it down, which hides what it runs."
    phrase      = "builds a command out of numbers"
    description = "A chain of six or more character codes handed to fromCharCode, three or more chr calls added together, or a hex, rot13 or reversed-string decode within 200 bytes of an exec, eval or subprocess call. The text the reader sees is arithmetic, and the command only exists once it runs, which is how the obfuscated skill scripts kept their fetch out of every string search. One fromCharCode for a keystroke, a hex colour parsed with fromhex, and a reversed list with no execution anywhere near it are ordinary code and stay silent."
    references  = "https://snyk.io/articles/defending-against-glassworm/ https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    $fromcharcode = /(String\.)?fromCharCode\s*\(\s*\d{1,3}(\s*,\s*\d{1,3}){5,}/
    $chr_plus     = /chr\s*\(\s*\d{1,3}\s*\)\s*\+\s*chr\s*\(/

    $convert = /(bytes\.fromhex|binascii\.unhexlify|codecs\.decode\s*\([^\n)]{0,60}rot[_-]?13|\brot13\b|\[::-1\]|\.reverse\(\)\s*\.join\(|\bjoin\s*\([^\n)]{0,40}\bchr\s*\(|\btr\s+['"]?A-Za-z['"]?\s+['"]?N-ZA-Mn-za-m)/ nocase

    $exec_shell  = /\b(bash|zsh|\/bin\/sh|sh[ \t]+-c)\b/
    $exec_call   = /\b(eval|exec|execSync|execFile|execFileSync|spawn|spawnSync|Function|popen|system|subprocess|child_process|os\.system|check_output)\b/

  condition:
    item.file_type == "text" and (
      $fromcharcode
      or #chr_plus >= 3
      or for any i in (1..#convert): (
        for any of ($exec*): ($ in (math.max(@convert[i], 200) - 200..@convert[i] + 200))
      )
    )
}
