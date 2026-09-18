---
status: accepted
date: 2026-09-18
---

# AI Judgement treats the engine as an untrusted witness

AI Judgement hands attacker-written content to a language model and shows the result to people who may not be technical. The research probe showed the smallest engine (Apple on-device, 3B) flipping to "benign, approved" on a single injected sentence. We decided not to try to make the engine trustworthy and to bound what any Verdict can do instead.

Exactly one Judgement Engine is active, chosen by the user; nothing falls back to another engine on error, in particular never across the boundary between this machine and the Claude API. An engine error is no Verdict, never benign. Every engine receives the same redacted Judgement Request, so there is one redaction path to test and the local engines get no more than the cloud one. Ollama only counts as local on a loopback address that is an AgentSweep setting; `OLLAMA_HOST` is never read.

A malicious Verdict counts only if it quotes the Item and the core finds each quote in what was sent; without a verifiable quote it is discarded. A benign Verdict is recorded as unsure when a Heuristic marked `reviewer_directed` fired on the Item, so the one thing an in-file injection can achieve, clearing its own Item, is closed by a deterministic check rather than by prompt wording. The engine's `reason` text is shown only on malicious Verdicts, as length-capped plain text beneath the deterministic Heuristic explanations; benign and unsure use AgentSweep's own fixed wording. Severity never comes from the engine. Because Ambiguous Items are already hidden from the Simple posture, the worst a fully compromised engine can do is what happens with AI Judgement switched off, plus false accusations that the quote check and a shipping bar (at most 2% false malicious on the benign corpus, per engine, re-measured per Apple model version) keep rare.

## Considered options

- A fallback chain (Claude, then Ollama, then Apple): rejected because the user could no longer tell which engine judged an Item, cached Verdicts would not be comparable, and a silent move between cloud and local breaks the consent each side was given under.
- Lighter or no redaction for local engines: rejected; Ollama is a third-party process, and two redaction paths mean two things to get wrong.
- Trusting a hardened prompt to resist injection: rejected as unmeasurable for a 3B model; the prompt still frames the content as untrusted data, but nothing depends on that holding.
- Dropping the quote check so the Apple engine passes more often: rejected; if an engine cannot quote, the eval decides whether it ships, not a weaker check.
- Showing the engine's reason on every Verdict: rejected because a benign reason is attacker-influenced text ("safe, click Trust") shown exactly where the user decides.
