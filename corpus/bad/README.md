# The bad corpus

Samples modelled on documented incidents and proofs of concept, defanged so that none of them works as the thing it is modelled on. The corpus is the first of the three sets of the AI Judgement eval in spec section 4.4; the bad Fixtures of the Heuristics are the rest of its bad set, because a T1 Fixture never reaches T3. Spec section 4.2 fixes its shape: one directory per public source, each with a provenance file.

The samples are written by a person, never by an agent. Until they exist the corpus holds only this file, the runner reports every class T3 can see as insufficient, and no eval result counts.

## Layout

One directory per source, named after the incident or proof of concept in a short lowercase slug. In it:

- A `PROVENANCE.md`, described below.
- One directory per sample, named in the same way. A source holds at least one.

Each sample directory holds a `sample.toml` and what the Surface Adapters would find on a machine that carries it:

- `home/` is laid out as the home directory: `.claude.json`, `.claude/` and `.codex/` with everything under them, exactly where Claude Code and Codex keep them.
- `project/` is laid out as one project root: its instruction files, `.mcp.json`, `.claude/`, `.codex/`, `.agents/`, `.env` and so on. A path segment named `dot-git` is laid out as `.git`, because git refuses to commit a directory of that name. A file under `dot-git/hooks/` is given the execute bit when it is laid out.
- `before/` is optional and holds a `home/` and a `project/` of its own, as they stood when the Baseline was taken. With it, every Item of the sample is compared with that layout and is unchanged, changed or added; this is how a sample of class 5 shows a change to a user-level Surface. Without it no Item has a Baseline, which is what a first Scan sees.

A sample needs a `home/` or a `project/`, and the adapters must find at least one Item in it; a sample laid out where no Agent looks proves nothing and fails the run.

`sample.toml` has these keys and no others:

- `title`: one line naming what the sample is.
- `class`: the ranked class of spec section 2.3 it belongs to, 1 to 6.
- `row`: the row of the attack catalogue in `docs/research/` it is modelled on.
- `tracked`: optional, the project paths the repository commits. With it, the project is laid out as a repository whose index tracks exactly those paths; the runner writes the index itself and never runs a git binary. A sample whose `dot-git` is a gitdir pointer file is left as it is.

## The provenance file

Every source directory has a `PROVENANCE.md` with two sections, each a level two heading spelled exactly as here:

- `## Public source` names the public write-up, advisory or proof of concept the samples are modelled on, with enough detail (title, publisher, date, and where it can be read) for a reviewer to find it. A link to it is written with its host's top-level domain replaced by `.invalid`, because the lint holds the provenance file to the same rules as the samples.
- `## Defanged` says, sample by sample, what was changed from the original so that it no longer works: which hosts were replaced, which payloads were reduced to an `echo`, what was left out.

## Defanging rules

The lint in the corpus runner reads every file of every source, the provenance file included, and refuses the whole corpus when one breaks a rule. The rules:

- Every host ends in `.invalid`. The lint reads as a host the host of anything written as a URL, whatever its last label, and every bare dotted name whose last label is a public top-level domain. A dotted name that ends in a file extension is read as a file.
- An IPv4 address is one nobody can route to: the documentation ranges of RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), loopback, link-local or a private range.
- Every encoded payload decodes to a single `echo` with nothing chained, piped, redirected or substituted after it. The lint decodes base64 runs of sixteen characters or more, runs of four or more `\x` escapes and bare hex strings of eight digits or more; one that decodes to readable text must be a lone `echo`. One that decodes to bytes that are not text stays silent.
- Every file is UTF-8 text. A file the lint cannot read is one nobody has proven defanged.
- Every source has its provenance file with both sections, and every sample has its `sample.toml` and something laid out.

What the lint cannot check, the author holds to by hand: no real credential, token, key or personal value from any machine; no working command where a payload stood, in plain text or encoded in a way the lint does not decode; no binary.

## Running it

The run is `cargo run -p agentsweep-xtask -- bad-corpus`. It lints the corpus, lays every sample out in a temporary directory of its own, scans every Item the adapters find there with the bundled Rule Pack and removes the directory again; the real home is never read. The report lists every sample with each of its Items, the T1 Rules and Heuristics that fired, the Score, the Band, and whether the Item reaches T3. It names the classes with no sample and counts the bad set per ranked class, corpus samples and bad Heuristic Fixtures side by side. An eval result counts only once the corpus holds at least three samples for each class T3 can see (classes 1 to 5; Exposure never reaches T3) and thirty in all; until then each short class and the total say insufficient. The same run is part of the default test suite.
