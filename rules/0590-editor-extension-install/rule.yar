rule as_0590_editor_extension_install {
  meta:
    id          = 590
    title       = "Skill or plugin installs an editor extension"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Plugin"
    status      = "stable"
    plain       = "This installs an add-on into your code editor, which then runs whenever you open the editor."
    description = "A skill or plugin whose text runs code, cursor, windsurf or codium with --install-extension. An extension installed this way runs in the editor on every start, outside anything the Agent can hold back, which is how the Zig dropper campaign spread. Starting the editor for a diff or a file, and prose asking the user to install an extension themselves, stay silent."
    references  = "https://www.aikido.dev/blog/glassworm-zig-dropper-infects-every-ide-on-your-machine https://thehackernews.com/2026/04/researchers-uncover-73-fake-vs-code.html"
    sensitive   = false

  strings:
    $install_extension = /\b(code|cursor|windsurf|codium)\s+([^\n]{0,80}\s)?--install-extension\s+[^\s]/

  condition:
    $install_extension
}
