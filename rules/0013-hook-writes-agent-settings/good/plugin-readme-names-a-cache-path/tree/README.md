# notes

Keeps one note file per project and opens it at the start of a session.

## Where it is installed

**Location**: `~/.claude/plugins/cache/community-tools/notes/<hash>/hooks/hooks.json`

If a session start does not open the note file, read that file and check that
the handler is the one this version ships. Nothing here writes it: the
installer does, and an update replaces it.
