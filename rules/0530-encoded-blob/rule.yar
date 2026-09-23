rule as_0530_encoded_blob {
  meta:
    id          = 530
    title       = "A long encoded blob in text the agent reads"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,Plugin,InstructionFile,Hook,Subagent"
    status      = "stable"
    plain       = "This file carries a long block of encoded text, so what it really says cannot be read."
    description = "An unbroken base64 run of 200 characters or more. The ClawHavoc skills carried their stealer this way, and Snyk found the same shape in the ToxicSkills sample set, because encoded text passes a human reading the file and still reaches whatever decodes it later. Three shapes carry a long run for an honest reason and are excluded: a data URI for an inline image or font, the body of a PEM block, and a JSON web token. The decode-and-run chain around a blob is rule 0001's; this notices the blob itself, and it is weight 1 because a blob on its own proves nothing."
    references  = "https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/ https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ docs/research/attack-catalogue.md#1"
    sensitive   = false

  strings:
    $blob     = /[A-Za-z0-9+\/]{200,}={0,2}/
    // data:image/png;base64,<blob> and its kin, the blob's honest carrier
    $data_uri = /data:[A-Za-z0-9.+\/-]{0,60};base64,/ nocase
    $pem      = /-----BEGIN [A-Z0-9 ]{1,40}-----/
    $jwt      = /\beyJ[A-Za-z0-9+\/_-]{10,}\.[A-Za-z0-9+\/_-]{10,}\.[A-Za-z0-9+\/_-]{10,}/

  condition:
    item.file_type == "text"
    and for any i in (1..#blob): (
      not for any j in (1..#data_uri): (
        @data_uri[j] < @blob[i] and @blob[i] - @data_uri[j] < 120
      )
      and not for any j in (1..#pem): (
        @pem[j] < @blob[i] and @blob[i] - @pem[j] < 400
      )
      and not for any j in (1..#jwt): (
        @jwt[j] <= @blob[i] and @blob[i] < @jwt[j] + !jwt[j]
      )
    )
}
