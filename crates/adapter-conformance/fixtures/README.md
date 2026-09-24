# Fixture trees

One tree per case, at `fixtures/<agent id>/<case>/`, with the enumeration it
must produce recorded beside it in `<case>.snapshot`.

A tree is the structure of a real install with harmless contents: hosts are
`.invalid`, payloads decode to nothing, and no value in one is a secret. A case
directory is the project root, unless it holds both a `home` and a `project`
directory, which are then the fake home and the fake project the Host is built
from. A `system` directory beside those two stands in for the absolute system
paths a Managed Surface lives at, so no case ever reads the real `/Library` of
the machine it runs on.

A registry records a project by its absolute path, which nobody can write down
before the copy exists. A fixture file may therefore name the copy with
`{{home}}`, `{{project}}` and `{{root}}`, and the copy puts the real paths in.
Use a placeholder only where the path does not reach an Item's content: a
content hash that moved with the directory a tree happened to land in would
make Trust and the Baseline meaningless, and the suite enumerates a second,
independent copy of every case to say so.

Two names cannot be committed as they are, so they are committed with a `dot-`
prefix and get their leading dot back on the temporary copy the suite reads: a
directory called `.git` would become part of this repository, and a file called
`.env` is ignored by it. A hook that git would run is committed with its
execute bit, which is what makes it an Item.

A symbolic link is committed the same way round: a file whose name ends in
`.symlink`, holding the target on one line, becomes that link on the copy. Most
skills on a real machine are links into a shared directory, and a link
committed as a link would be followed by everything that reads this repository.
Keep the target relative, so a case reads the same wherever it was copied to.

A tree Item's snapshot lists every file of its manifest with its size, whether
a Rule was run over it and what kind of file it is. That is where a case says
what is excluded (git internals), what is listed without being scanned (a
vendored dependency directory) and what a Rule about native executables in a
skill would see.

No tree carries a git index. Nothing here is tracked by the repository it
pretends to be, so Provenance in these snapshots is "manual"; the Repository
Provenance path is covered where an index can be written, in the workspace
adapter's own tests and in the Folder Scan's.

A file an Agent writes as JSON is committed the way that Agent writes it: two
spaces of indentation, the keys in the order they were written, one trailing
newline. The suite quarantines one entry out of such a file and puts it back,
and asks for the file it started with, byte for byte; a file in any other style
would come back in the style AgentSweep writes and the case would fail for a
reason that is about the fixture rather than about the adapter.

Record a snapshot by running the suite once with `AGENTSWEEP_UPDATE_SNAPSHOTS=1`
and reading the result before committing it.
