// GENERATED from iocs/files.txt by the pack build. Do not edit by hand.
rule as_0903_ioc_files {
  meta:
    id          = 903
    title       = "File name dropped by a known campaign"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Workflow,ExecPolicy,Generic"
    status      = "probation"
    plain       = "This item carries a file that a known attack campaign drops."
    phrase      = "carries a file a known attack drops"
    description = "File names taken from published incident reports (iocs/files.txt), matched as the last path component of the file of a tree the scan is on or of the Item's own path, which is what catches a dropped file whose own bytes say nothing. The content is never read: a .gitignore or a README that names a listed file is not that file and stays silent, and so does a longer name that merely ends with an entry, such as tsconfig.tsbuildinfo. Regenerated on every pack build."
    references  = "docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    item.file matches /(^|\/)\.tsbuildinfo$/
    or item.path matches /(^|\/)\.tsbuildinfo$/
    or item.file matches /(^|\/)setup_bun\.js$/
    or item.path matches /(^|\/)setup_bun\.js$/
    or item.file matches /(^|\/)bun_environment\.js$/
    or item.path matches /(^|\/)bun_environment\.js$/
    or item.file matches /(^|\/)results\.b64$/
    or item.path matches /(^|\/)results\.b64$/
}
