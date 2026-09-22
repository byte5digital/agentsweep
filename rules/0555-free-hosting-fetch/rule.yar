rule as_0555_free_hosting_fetch {
  meta:
    id          = 555
    title       = "Something fetched from free hosting, dynamic DNS or a giveaway domain"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,Plugin,Hook,McpServer"
    status      = "stable"
    plain       = "This downloads something from a place that costs nothing to set up and nothing to walk away from."
    description = "A transfer command whose address sits on free application hosting, on a dynamic DNS provider, or on one of the registration-free top level domains. Anyone can stand such a host up in a minute and abandon it the same day, which is what the payload servers of the skill campaigns did. Only a fetch counts: the same host named in prose, in a documentation link or in a comment stays silent, because project pages and preview deployments live on exactly these services. Weight 1, since honest install lines point at them too; the list lives in the rule because these service names do not rot."
    references  = "https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $fetch_free  = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|fetch)\b[^\n]{0,60}https?:\/\/[A-Za-z0-9.-]{1,60}\.(pages\.dev|workers\.dev|netlify\.app|vercel\.app|github\.io|web\.app|firebaseapp\.com|glitch\.me|repl\.co|replit\.dev|surge\.sh|000webhostapp\.com|herokuapp\.com|fly\.dev|onrender\.com|railway\.app|duckdns\.org|no-ip\.org|no-ip\.com|ddns\.net|hopto\.org|zapto\.org|sytes\.net|myftp\.org|dynu\.net|nip\.io|sslip\.io)([\/:"'\s]|$)/
    $fetch_cheap = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|fetch)\b[^\n]{0,60}https?:\/\/[A-Za-z0-9.-]{1,60}\.(tk|ml|ga|cf|gq|top|icu|click|cyou|sbs)([\/:"'\s]|$)/

  condition:
    any of them
}
