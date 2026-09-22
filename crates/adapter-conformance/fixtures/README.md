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

No tree carries a git index. Nothing here is tracked by the repository it
pretends to be, so Provenance in these snapshots is "manual"; the Repository
Provenance path is covered where an index can be written, in the workspace
adapter's own tests and in the Folder Scan's.

Record a snapshot by running the suite once with `AGENTSWEEP_UPDATE_SNAPSHOTS=1`
and reading the result before committing it.
