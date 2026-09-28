rule as_0535_sibling_file_decoder {
  meta:
    id          = 535
    title       = "Code that runs the contents of a file hidden beside it"
    tier        = 2
    weight      = 3
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Plugin"
    status      = "stable"
    plain       = "This item runs whatever is inside another file it ships, so the part that acts is not the part you read."
    description = "Reading a file out of assets, build, dist, node_modules or a hidden directory of the same item and handing its contents to exec, eval or a shell, sourcing a file out of an asset or hidden directory, or running a data file with an interpreter. The Cloak and Detonate study found the payload moved into exactly the directories a scanner skips, with a harmless looking decoder in the file the reviewer reads, and better than nine in ten scanners missed it. The Heuristic holds to that decoder shape and no wider: starting a program that ships with the item, such as node dist/server.js, stays silent, because it is how nearly every plugin server starts and running a shipped program is not decoding a hidden one. Activating a virtual environment stays silent too."
    references  = "https://arxiv.org/abs/2607.02357 https://thehackernews.com/2026/07/new-skillcloak-technique-lets-malicious.html docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    // exec(open("assets/payload.dat").read())
    $eval_open   = /\b(exec|eval)\s*\(\s*[^\n]{0,60}\bopen\s*\(\s*['"][^'"\n]{0,80}(assets|build|dist|out|node_modules|\.[A-Za-z0-9_-]{1,20})\/[^'"\n]{1,60}['"]/
    // eval(fs.readFileSync("build/payload.txt", "utf8"))
    $eval_read   = /\b(eval|Function)\s*\(\s*[^\n]{0,80}(readFileSync|readFile)\s*\(\s*[^\n]{0,80}(assets|build|dist|out|node_modules|\.[A-Za-z0-9_-]{1,20})\//
    // eval "$(cat .cache/stage)"
    $eval_cat    = /\beval\s+["']?\$\(\s*(cat|head|tail|xxd|base64|openssl)\s+[^)\n]{0,60}(assets|build|dist|out|node_modules|\.[A-Za-z0-9_-]{1,20})\//
    // source .git/hooks/env, . assets/setup
    $source_file = /(^|[\s;&|])(source|\.)[ \t]+["']?(\.\/)?[^\s;&|"']{0,40}(assets|\.git|\.cache|\.data|\.bin|\.tmp|\.claude|\.codex|\.agents)\/[^\s;&|"']{1,60}/
    // node .cache/bundle.dat, python3 assets/notes.png
    $run_data    = /\b(bash|sh|zsh|node|python3?|perl|ruby|osascript)[ \t]+["']?(\.\/)?[^\s;&|"']{0,40}(assets|build|dist|out|node_modules|\.git|\.cache|\.data|\.bin|\.tmp|\.claude|\.codex|\.agents)\/[^\s;&|"']{1,60}\.(bin|dat|txt|b64|log|json|png|jpg|jpeg|gif|svg|cache|tmp|enc|md|csv|ico|woff)\b/

  condition:
    item.file_type == "text" and any of them
}
