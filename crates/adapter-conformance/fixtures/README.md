# Fixture trees

One tree per case, at `fixtures/<agent id>/<case>/`, with the enumeration it
must produce recorded beside it in `<case>.snapshot`.

A tree is the structure of a real install with harmless contents: hosts are
`.invalid`, payloads decode to nothing, and no value in one is a secret. A case
directory is the project root, unless it holds both a `home` and a `project`
directory, which are then the fake home and the fake project the Host is built
from.

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
