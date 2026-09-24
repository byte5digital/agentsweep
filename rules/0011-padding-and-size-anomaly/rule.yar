rule as_0011_padding_and_size_anomaly {
  meta:
    id          = 11
    title       = "An instruction file padded or grown far past any readable size"
    tier        = 1
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Workflow"
    status      = "probation"
    plain       = "This file is far bigger or emptier than anything meant to be read, which is how instructions are hidden from a reviewer."
    description = "One of three shapes on a file an Agent reads as instructions: over 1 MB of bytes, whitespace at or above 90 per cent of a file over 64 KB, or more than a thousand consecutive blank lines. All three are padding, and padding has one purpose here: push the payload past where a reviewer scrolls and past where a scanner that truncates stops reading. Trail of Bits found skills carrying a 22 MB README, and the ClawHub listings Unit 42 walked used the same trick with a hundred thousand leading newlines. AgentSweep never truncates, so the padding is not what hides the instruction from AgentSweep; the size itself is the tell. The three limbs are separate because the shapes are: a large file need not be empty and an empty one need not be large. A long generated document that is genuinely read stays under the whitespace share, a formatted file with paragraph breaks stays far under a thousand blank lines in a row, and a file of 60 KB of indentation is under the size floor the whitespace limb carries."
    references  = "https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/ https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  condition:
    filesize > 1048576
    or (item.whitespace_percent >= 90 and filesize > 65536)
    or item.max_blank_run > 1000
}
