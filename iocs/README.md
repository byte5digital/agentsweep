# Indicator lists

Plain-text indicator lists rendered into generated rules with fixed ids by the pack build. One entry per line, `#` comments allowed, entries are exact strings unless the list says otherwise. Indicators rot, so they ship in the rule feed and are edited here, never inside a hand-written rule.

| List | Generated rule | Matches |
|---|---|---|
| `hosts.txt` | `rules/0900-ioc-hosts` | the host as a case-insensitive whole word in any scanned bytes |
| `ips.txt` | `rules/0901-ioc-ips` | the address as a whole word in any scanned bytes |
| `packages.txt` | `rules/0902-ioc-packages` | `mcp.package` equal to the entry, or the entry as a whole word in command text |
| `files.txt` | `rules/0903-ioc-files` | the file name as a path component in any scanned bytes or tree manifest |

Both the list and the generated `rule.yar` are committed; CI regenerates and fails if they differ. Generated rules are tier 1 threats, severity critical, and follow the same probation rule as any other. Sources for every entry are in `docs/research/attack-catalogue.md`, section 3, item 22. Entries below are defanged in the catalogue with `[.]`; here they are written plainly because they are matched, not linked.
