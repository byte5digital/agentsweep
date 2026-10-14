// The Posture the window is shown in: the one place every screen of the
// window asks "which Posture" (spec section 8.2). One UI; a Posture changes
// wording and density, never what is listed.
//
// The app sends the Posture with every view it hands the window, read from
// the daemon's settings and followed from its settings-changed event; this
// module only keeps it. A screen reads `posture()` or `isDeveloper()` while
// it renders, and one that keeps something rendered between views listens
// with `onPostureChange`. The stylesheet can follow `data-posture` on the
// root element.

const POSTURES = ["simple", "developer"];

let current = "simple";
const listeners = new Set();

document.documentElement.dataset.posture = current;

// The Posture in force: "simple" or "developer".
export function posture() {
  return current;
}

// True in the Developer Posture.
export function isDeveloper() {
  return current === "developer";
}

// Calls `listener` with the new Posture whenever it moves; answers a
// function that stops listening.
export function onPostureChange(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

// Takes the Posture of a view the app sent. A Posture this window does not
// know leaves it as it was.
export function takePosture(next) {
  if (!POSTURES.includes(next) || next === current) {
    return;
  }
  current = next;
  document.documentElement.dataset.posture = current;
  for (const listener of listeners) {
    listener(current);
  }
}
