rule as_0013_hook_writes_agent_settings {
  meta:
    id          = 13
    title       = "Hook writes the Agent's own settings"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Hook,Plugin"
    status      = "probation"
    plain       = "A hook rewrites the agent's own settings, which is how a permission you never granted gets switched on."
    phrase      = "rewrites the agent's own settings"
    description = "A write primitive (a shell redirect, tee, sed -i, a Python open in write or append mode, fs.writeFile and its kin) with one of the Agent's own settings files in the same statement: .claude/settings.json, a settings.local.json, ~/.claude.json, .codex/config.toml, .codex/hooks.json or a plugin's hooks/hooks.json. A hook runs before the permission flow does, so a hook that edits the permission file grants itself whatever it likes; the shape is documented in the injected-marketplace-plugin incident. Fires on every Provenance, because a hook the user pasted in themselves does the same thing. Reading the settings and writing a summary, appending to a memory file or a log, and writing the editor's or the build tool's own settings all stay silent, and so does the closing bracket of a placeholder in prose, which is why a README that names the path of a hooks file is not a write to it."
    references  = "https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins https://code.claude.com/docs/en/hooks https://code.claude.com/docs/en/settings-reference"
    sensitive   = false

  strings:
    // > ~/.claude/settings.json, >> settings.local.json, tee -a ~/.claude.json
    $write_redirect = /([^\w>-]>>?|\btee\s+(-a\s+)?)[^\n;|&]{0,120}(\.claude\/settings\.json|settings\.local\.json|\.claude\.json|\.codex\/config\.toml|\.codex\/hooks\.json|hooks\/hooks\.json)/
    // sed -i ... ~/.claude/settings.json
    $write_sed      = /\bsed\s+-i[^\n;|&]{0,120}(\.claude\/settings\.json|settings\.local\.json|\.claude\.json|\.codex\/config\.toml|\.codex\/hooks\.json|hooks\/hooks\.json)/
    // open(..., "w") and open(..., "a") on a settings file
    $write_python   = /\bopen\s*\(\s*[^\n]{0,120}(\.claude\/settings\.json|settings\.local\.json|\.claude\.json|\.codex\/config\.toml|\.codex\/hooks\.json|hooks\/hooks\.json)['"]\s*\)?\s*,\s*['"][aw]/
    // fs.writeFileSync(<a settings file>, ...) and its kin
    $write_node     = /\bfs\.(writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*[^\n]{0,120}(\.claude\/settings\.json|settings\.local\.json|\.claude\.json|\.codex\/config\.toml|\.codex\/hooks\.json|hooks\/hooks\.json)['"`]\s*\)?\s*,/

  condition:
    any of them
}
