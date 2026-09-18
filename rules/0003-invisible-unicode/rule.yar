rule as_0003_invisible_unicode {
  meta:
    id          = 3
    title       = "Invisible or deceptive Unicode in text an agent reads"
    tier        = 1
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin,McpServer,Hook,SettingsEntry"
    status      = "probation"
    plain       = "This file contains hidden characters that a person cannot see but the agent will read as instructions."
    description = "Runs of Unicode Tag characters (ASCII smuggling), runs of zero-width characters (bit-encoded payloads), runs of supplementary variation selectors or private-use code points (GlassWorm), bidirectional override or isolate controls in a file with no right-to-left script (Trojan Source), and escaped ANSI control sequences inside config entries (terminal deception). Single zero-width joiners in emoji, a byte-order mark at offset 0, basic variation selectors and isolated private-use icons are excluded because they occur in benign markdown; they are T2 indicators. Only text files are checked."
    references  = "https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/ https://trojansource.codes/ https://snyk.io/articles/defending-against-glassworm/ https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/"
    sensitive   = false

  strings:
    // U+200B, U+200C, U+200D, U+2060, U+FEFF as UTF-8, three or more in a row
    $zero_width_run         = /(\xe2\x80[\x8b\x8c\x8d]|\xe2\x81\xa0|\xef\xbb\xbf){3,}/
    // U+202A..U+202E and U+2066..U+2069
    $bidi_control           = /\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]/
    // U+E0000..U+E007F, three or more in a row
    $tag_run                = /(\xf3\xa0[\x80\x81][\x80-\xbf]){3,}/
    // U+E0100..U+E01EF, four or more in a row
    $variation_selector_run = /(\xf3\xa0[\x84-\x87][\x80-\xbf]){4,}/
    // U+E000..U+F8FF, sixteen or more in a row
    $private_use_run        = /(\xee[\x80-\xbf][\x80-\xbf]|\xef[\x80-\xa3][\x80-\xbf]){16,}/
    // ESC [ or ESC ] written as a JSON or TOML escape inside a serialised config entry
    $escaped_ansi           = /\\u001[bB][\[\]]/

  condition:
    item.file_type == "text" and (
      $zero_width_run or $tag_run or $variation_selector_run or $private_use_run
      or ($bidi_control and not item.has_rtl_script)
      or (item.shape == "entry" and $escaped_ansi)
    )
}
