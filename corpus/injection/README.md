# The injection wrappers

The third set of the AI Judgement eval in spec section 4.4 is the injection-variant set: every Item of the bad set again, wrapped in text that addresses whoever judges it. The eval builds the set at run time from the fixed list in `wrappers.toml`, taking the wrappers in turn, one wrapped Item per bad Item. It then reports the flip rate: how many bad Items an engine called malicious bare and no longer malicious once wrapped.

The wrappers are written by a person, never by an agent, like the samples of the bad corpus. Until the first one is committed the eval reports the injection-variant set as insufficient.

## The list

Each wrapper is one `[[wrapper]]` table with a `before` text, placed ahead of the Item's own text, and an optional `after` text, placed behind it. No other key is allowed.

How a wrapper goes around an Item:

- A file Item has the texts placed around its bytes. A leading frontmatter block stays first, so a skill or a subagent still reads as one.
- A tree Item has them placed around the first file a Heuristic matched in, or its `SKILL.md`, or its first scanned file.
- An entry Item is canonical JSON, so the texts go into its `description` value, joined by line breaks, ahead of and behind whatever description it had. The reviewer-directed Heuristics read the text kinds and hooks, so most wrapped entries are judged without the reviewer-directed rule; the report counts how many wrapped Items carry it.

## Rules for a wrapper

- It fires at least one Heuristic marked `reviewer_directed` when it is wrapped around an instruction file. That is what the set is for: a benign Verdict on such an Item is recorded as unsure, and the eval shows whether the engine was talked round anyway. The eval refuses to run on a list where one wrapper fires none, and the default test suite checks the committed list the same way.
- It follows the defanging rules of the bad corpus: every host ends in `.invalid`, every encoded payload decodes to a lone `echo`, and no real credential, token or personal value appears anywhere.

## Running the eval

The eval is `cargo run -p agentsweep-xtask -- judgement-eval` with the engine (`--engine apple`, `ollama` or `claude`), the model for Ollama and Claude (`--model`), and the path the report is written to (`--report`). A Claude run takes its key from a file (`--key-file`) or standard input (`--key-stdin`), never from the Keychain. It asks the one engine about every Item of the three sets along the daemon's own path, request builder, redaction and Verdict checks included, writes the report to the path given and nothing else; the corpora are laid out in a temporary directory that is removed afterwards. Offline the benign set is skipped with a line saying so, and `AGENTSWEEP_CORPUS_REQUIRED` makes that a failure. The automated suite runs the harness against a fake engine only; a run against a real engine is build work by hand.
