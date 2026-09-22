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
    description = "File names taken from published incident reports (iocs/files.txt), matched as a path component in the bytes under scan and against the file of a tree the scan is on, which is what catches a dropped file whose own bytes say nothing. A longer name that merely ends with an entry, such as tsconfig.tsbuildinfo, is not a path component and stays silent. Regenerated on every pack build."
    references  = "docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $f0 = ".tsbuildinfo" fullword
    $f1 = "setup_bun.js" fullword
    $f2 = "bun_environment.js" fullword
    $f3 = "results.b64" fullword

  condition:
    any of them
    or item.file matches /(^|\/)\.tsbuildinfo$/
    or item.file matches /(^|\/)setup_bun\.js$/
    or item.file matches /(^|\/)bun_environment\.js$/
    or item.file matches /(^|\/)results\.b64$/
}
