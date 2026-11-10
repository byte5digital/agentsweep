// Keeps the DOM nodes of a part of a page that did not change. Every stream
// event renders the page again, and on a busy Mac they come every few
// seconds; a button replaced between mouse-down and mouse-up gets no click.
// So a part is built again only when what it shows changed: `key` says what
// it shows (the JSON of what it is built from), and the part keeps its nodes,
// and the buttons in them, for as long as the key stays the same.

const built = new WeakMap();

// Fills `node` with what `build` returns, unless it was last filled from the
// same `key`. Answers true when it was filled again.
export function keep(node, key, build) {
  if (built.get(node) === key) {
    return false;
  }
  built.set(node, key);
  node.replaceChildren(...build());
  return true;
}
