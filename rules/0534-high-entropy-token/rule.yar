import "math"

rule as_0534_high_entropy_token {
  meta:
    id          = 534
    title       = "A long token of no recognisable kind"
    tier        = 2
    weight      = 1
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Skill,Hook"
    status      = "stable"
    plain       = "This file carries a long scrambled string that is not a key, an address or anything else with a name."
    description = "An unbroken run of 64 printable characters or more whose entropy is above 5.5, which is close to the most a character can carry and far above ordinary text, a path or a command. What is left once the shapes with an honest reason to look random are taken out is usually a packed payload or a key nobody can account for. Encoded runs are excluded, which covers base64, base64url, hex and the digests written in them, and so is anything that turns out to be a web address; a long encoded run on its own is heuristic 0530. Weight 1, because one unexplained string is only worth reading together with whatever else fired."
    references  = "https://arxiv.org/abs/2607.02357 https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/ docs/research/attack-catalogue.md#1"
    sensitive   = true

  strings:
    $token   = /[!-~]{64,}/
    // base64, base64url, hex and the digests written in them share this alphabet
    $encoded = /[A-Za-z0-9+\/=_-]{48,}/
    $url     = /[a-z][a-z0-9+.-]{1,12}:\/\/[!-~]{8,}/ nocase

  condition:
    item.file_type == "text"
    and for any i in (1..#token): (
      math.entropy(@token[i], !token[i]) > 5.5
      and not for any j in (1..#encoded): (
        @encoded[j] + !encoded[j] == @token[i] + !token[i] and !encoded[j] >= 48
      )
      and not for any j in (1..#url): (
        @url[j] + !url[j] == @token[i] + !token[i]
      )
    )
}
