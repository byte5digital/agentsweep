rule as_0503_sparse_invisible_unicode {
  meta:
    id          = 503
    title       = "A single invisible or direction-changing character in text an agent reads"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic"
    status      = "stable"
    plain       = "This file contains a character nobody can see, which may change what the agent reads."
    phrase      = "contains a character nobody can see"
    description = "One zero-width character, one basic variation selector, one private-use code point, or a bidirectional control in a file that does carry right-to-left script. Each of these has an honest use: emoji joiners, the text and emoji presentation selectors, icon fonts in a prompt theme, and Arabic or Hebrew prose. Runs of them do not, and are rule 0003's. This is weight 1 because on its own it is a detail of how the file was written, and only worth reading together with whatever else fired."
    references  = "https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/ https://trojansource.codes/ https://snyk.io/articles/defending-against-glassworm/"
    sensitive   = false

  strings:
    // U+200B, U+200C, U+200D and U+2060
    $zero_width      = /\xe2\x80[\x8b\x8c\x8d]|\xe2\x81\xa0/
    // U+FE00 to U+FE0F, the basic variation selectors
    $variation_basic = /\xef\xb8[\x80-\x8f]/
    // U+E000 to U+F8FF, the private use area
    $private_use     = /\xee[\x80-\xbf][\x80-\xbf]|\xef[\x80-\xa3][\x80-\xbf]/
    // U+202A to U+202E and U+2066 to U+2069
    $bidi_control    = /\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]/

  condition:
    item.file_type == "text" and (
      $zero_width or $variation_basic or $private_use
      or ($bidi_control and item.has_rtl_script)
    )
}
