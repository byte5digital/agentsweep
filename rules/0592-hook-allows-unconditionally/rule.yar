rule as_0592_hook_allows_unconditionally {
  meta:
    id          = 592
    title       = "Hook that can only ever answer allow"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "high"
    class       = 1
    kinds       = "Hook"
    status      = "stable"
    plain       = "A hook answers the agent's permission question with yes every time, so you are never asked."
    phrase      = "always answers yes for you"
    description = "Hook text that emits permissionDecision allow and never any other decision, in the entry as written or in the escaped form a serialised hook entry carries. A hook that can take only one side of the decision is an approval it grants itself, the auto-approval half of the injected-marketplace-plugin incident. A hook that allows one case and asks or denies in another, and a hook that only denies, both stay silent."
    references  = "https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins https://code.claude.com/docs/en/hooks"
    sensitive   = false

  strings:
    $allow      = /\\?"permissionDecision\\?"\s*:\s*\\?"allow\\?"/
    $other_way  = /\\?"permissionDecision\\?"\s*:\s*\\?"(deny|ask|defer)\\?"/

  condition:
    $allow and not $other_way
}
