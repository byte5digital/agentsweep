# TypeSafe (Jev) as a classifier for the AI Judgement tier (T3)

Research ticket: `.scratch/agentsweep/issues/17-typesafe-classifier.md`. Date: 2026-09-17.

Question: can TypeSafe's hosted "System One" model (https://docs.typesafe.ai/) serve as a fast, cheap classifier for AgentSweep, either as a T3 engine or as a signal feeding the T2 ambiguity band, and what would it cost us in the standing "nothing leaves the machine" preference.

Method: every page linked from https://docs.typesafe.ai/llms.txt was read (introduction, concepts, primitives, confidence, patterns, models, api, legal, sdk, agent-skill, model-jaggedness, four cookbooks). No probe was run; there is no API key. Everything below is what the docs state, with the page it came from. Claims not found on the docs site are listed in section 8.

## 1. What it is

- A hosted API only. The model is "Jev", "TypeSafe's flagship model and the first System One model". You send a `state` (the content) plus a map of typed `questions`; it "returns structured results directly. No text generation, no parsing." It "does not write replies, produce code, or generate explanations of their reasoning." Source: https://docs.typesafe.ai/ and https://docs.typesafe.ai/concepts/system-one
- "Typesafe" means typed answers: each answer is constrained to the options supplied and comes back as a value plus a probability distribution, never free text. The docs never use the word "classifier".
- Questions are zero-shot. Each has a `type` (`choice` | `score` | `noul`), natural-language `instructions`, and `criteria`. Choice takes up to 255 named options with descriptions; Score takes an ordered list of at least two levels; Noul is a yes/no probability. Criteria and instructions may be strings, objects or arrays, so worked examples can be embedded as JSON. Source: https://docs.typesafe.ai/primitives, https://docs.typesafe.ai/primitives/choice, https://docs.typesafe.ai/primitives/advanced, https://docs.typesafe.ai/api
- Delivery: `POST https://api.typesafe.ai/v1/systemone` with a bearer API key; Python SDK `typesafe-sdk` (Python 3.10+); JS SDK `@typesafe-ai/sdk` (Node 20+, https://github.com/typesafe-ai/typesafe-sdk-js); web playground at console.typesafe.ai; an agent skill for Claude Code and Codex (https://github.com/typesafe-ai/skills). No Rust SDK; the HTTP API is plain JSON so a `reqwest` client is trivial. Source: https://docs.typesafe.ai/sdk, https://docs.typesafe.ai/agent-skill

## 2. Runtime: nothing runs locally

- Every classification is a network call to `api.typesafe.ai`. No page mentions a local model, WASM, offline mode, on-prem or self-hosting; there is no deployment page in the docs index. The Python SDK accepts a `base_url`, but nothing says the model can be run by the user. Source: https://docs.typesafe.ai/sdk, https://docs.typesafe.ai/models
- Consequence for AgentSweep: TypeSafe can only ever be an opt-in cloud engine in the same class as the Claude API path. It cannot be the local default, and it cannot sit inside T2 (which is local heuristics by definition).

## 3. Model, limits, speed

- Current model `jev-1.13.0`; aliases `jev-latest` and `jev-preview` both resolve to it. Cookbooks were run on `jev-1.12`. `GET /v1/models` lists versions with release dates. Source: https://docs.typesafe.ai/models
- Training method is called RLCD, "Reinforcement learning for calibrated decisions": the model is trained to return decisions and calibrated probabilities instead of text. Calibration claim: outcomes given p=0.8 occur about 80% of the time across groups of predictions. Source: https://docs.typesafe.ai/introduction/machine-learning-primer, https://docs.typesafe.ai/confidence
- Context: 64k tokens for all `state` plus `questions` together; 32k tokens for `state` plus the longest single question, "roughly 150,000 characters of English text". Source: https://docs.typesafe.ai/model-jaggedness/jev-1.13, https://docs.typesafe.ai/primitives
- Speed: no latency SLA. All questions in one request are evaluated in parallel; "adding questions barely changes the response time". The parallel-questions cookbook (jev-1.12, a 54,000-character document, 13 questions) reports 0.27 s for one batched call versus 2.71 s for 13 sequential calls. Source: https://docs.typesafe.ai/cookbooks/parallel_questions
- Not stated: parameter count, architecture, supported languages (only English is mentioned).

## 4. Pricing and rate limits

- Jev 1.13: $0.042 per million input tokens; output tokens are free. Rate limit 250,000 tokens per second and 1,200 requests per minute; `429` when exceeded, `529 Overloaded` also documented; limits "can change without notice"; higher limits via sales@typesafe.ai. No free tier is documented. Source: https://docs.typesafe.ai/models
- Worked cost for the same workload used in the local-engines research (100 files of 5 KB, about 125K input tokens plus question overhead): roughly $0.005 to $0.01 per full pass. That is about 40 to 70 times cheaper than Claude Haiku 4.5 ($0.34) and about 100 times cheaper than Sonnet 5 ($0.78). At 1,200 requests per minute a full-scan burst is not rate-limited for a single user.

## 5. Input and output shape versus the T3 verdict schema

- Input is text only: string, JSON object, or array of strings. Images and files are not supported. Code is treated as text; the Choice page uses programming-language detection as an example, and the hierarchical cookbook classifies queries into a repo file tree. Fields of a JSON state can be referenced by path inside instructions. Source: https://docs.typesafe.ai/concepts/state
- Output per question: Choice returns `choice`, `probabilities` (sum to 1) and `confidence`; Score returns a probability-weighted `score` plus `legend`, `probabilities`, `confidence`; Noul returns `noul` (0 to 1). Top level carries `model` and `usage.input_tokens`. Source: https://docs.typesafe.ai/api
- Mapped onto the shared T3 verdict `{malicious, category, reason}` decided in the local-engines research: `malicious` maps to a Noul probability, `category` to a Choice over the attack catalogue classes, but `reason` cannot be produced at all. The model gives no explanation. A Simple-posture user would see "82% likely malicious, category: exfiltration" with no sentence saying why.
- The calibrated probability is a natural fit for the T2 ambiguity band's thresholds, and the guardrails cookbook does exactly that (review at 0.35, action at 0.70, or 0.85 permissive). Source: https://docs.typesafe.ai/cookbooks/llm_guardrails

## 6. Adversarial robustness: the same weakness as the Apple on-device model

- The jaggedness page for jev-1.13 says the model "does not treat [state] as hostile by default" and that injected instructions in the state "can move the answer. We expect to improve on this in the future." Other listed weaknesses: literal reading, counting and arithmetic, date comparison, indirection, large irrelevant state, contradictory instructions. Source: https://docs.typesafe.ai/model-jaggedness/jev-1.13
- The RAG cookbook shows a planted forum injection scored 0.99 on a `contains_prompt_injection` Noul, and the guardrails cookbook scored the DAN jailbreak 0.98, but both are small hand-picked samples run on jev-1.12, and the RAG page states "Nothing here is a security boundary." Source: https://docs.typesafe.ai/cookbooks/classifying_rag_passages, https://docs.typesafe.ai/cookbooks/llm_guardrails
- So the item under judgement, which is hostile input by design in AgentSweep, can steer the verdict. This is the same failure the Apple on-device model showed in the local-engines probe. The mitigation would be identical: T2 pre-screens for injection text and the verdict stays advisory.

## 7. Data handling and company

- The legal page says the DPA covers data retention, the privacy policy states "our commitment not to train models on user data", and zero data retention is offered to enterprise customers via privacy@typesafe.ai. Retention period, hosting region and compliance certifications are not on the docs site; they live at https://typesafe.ai/legal/data-processing and https://typesafe.ai/legal/privacy-policy (not read). Source: https://docs.typesafe.ai/legal
- Maker: TypeSafe (typesafe.ai). The primer states RLHF "was co-invented by Diogo Almeida, cofounder of TypeSafe". Launch date, location, funding and SDK licences are not stated. Source: https://docs.typesafe.ai/introduction/machine-learning-primer

## 8. Not found on the docs site

Model size and architecture; supported languages; latency SLA; free tier; local, on-prem or self-hosted runtime; custom training or fine-tuning; retention period and region; company launch date; SDK licences.

## 9. Assessment for AgentSweep

- **Cannot replace the local default.** It is hosted only, so the standing preferences (local by default, no hosted judgement service, nothing leaves the machine except the rule feed and the opt-in Claude call) rule it out as the default T3 engine. It could only join as a second opt-in cloud engine with the user's own key, and the legal pages would need reading first.
- **Where it genuinely wins**: cost (two orders of magnitude below Claude) and speed (sub-second, batched questions), and calibrated probabilities that slot straight into threshold logic. For a user who has opted into cloud judgement anyway, judging every T2 flag rather than only the ambiguous band becomes affordable.
- **Where it loses**: no `reason` field, so it cannot satisfy the Simple posture's plain-language explanation on its own; documented susceptibility to injected instructions in the state, the exact adversarial condition AgentSweep operates in; zero-shot only, so quality on malicious skill files, hooks and MCP configs is unverified; a second vendor and key for non-technical users to manage.
- **Plausible shapes for the T3 design ticket to weigh**: (a) reject, keep Claude as the only cloud engine; (b) accept as an opt-in "fast cloud" engine whose verdict is shown as probability plus category, with the reason line supplied by the matching T2 indicator text; (c) accept as a cheap pre-classifier in front of the Claude call, so Claude only writes a reason for items TypeSafe scores above a threshold. Any accept path needs a benchmark against the known-bad corpus before it goes in the spec.
