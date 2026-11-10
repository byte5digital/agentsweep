// Names every press of a button that asks the daemon for something, unique
// across reloads of the page, so the app carries out each press once even
// when the webview delivers it twice.

const loaded = crypto.getRandomValues(new Uint32Array(2)).join("-");
let presses = 0;

export function nextPress() {
  presses += 1;
  return `${loaded}-${presses}`;
}
