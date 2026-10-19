// The popover (spec section 8.1). It renders the view the app hands over and
// calls the app's commands; it decides nothing. It stays minimal: the orb,
// one sentence or the banner that replaces it, the last check and four
// buttons. While a Scan runs the sentence says "Checking now." and nothing
// more is shown here.

import { renderBanner } from "./banner.js";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const root = document.querySelector(".popover");
const said = document.getElementById("said");
const sentence = document.getElementById("sentence");
const detail = document.getElementById("detail");
const banner = document.getElementById("banner");
const lastCheck = document.getElementById("last-check");
const asking = document.getElementById("asking");
const openWindow = document.getElementById("open-window");
const scanNow = document.getElementById("scan-now");
const scanFolder = document.getElementById("scan-folder");
const scanLine = document.getElementById("scan-line");
const quit = document.getElementById("quit");

function when(text) {
  const moment = new Date(text);
  if (Number.isNaN(moment.getTime())) {
    return text;
  }
  return moment.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function render(view) {
  root.dataset.orb = view.orb;
  // A banner replaces the sentence and the line under it (spec section 8.6).
  said.hidden = view.sentence === null;
  sentence.textContent = view.sentence ?? "";
  detail.textContent = view.detail;
  detail.hidden = view.detail === "";
  renderBanner(banner, view.banner);
  if (view.lastCheck) {
    lastCheck.textContent = `Last check: ${when(view.lastCheck)}`;
    lastCheck.hidden = false;
  } else {
    lastCheck.hidden = true;
  }
  // When no daemon answers the app shows its banner and offers nothing else
  // (spec section 6.2).
  asking.hidden = view.protectionOff;
}

function say(line) {
  scanLine.textContent = line;
  scanLine.hidden = line === "";
}

quit.addEventListener("click", () => invoke("quit"));
openWindow.addEventListener("click", () => invoke("open_window"));
scanNow.addEventListener("click", async () => {
  try {
    say(await invoke("scan_now"));
  } catch (why) {
    say(String(why));
  }
});
scanFolder.addEventListener("click", () => invoke("scan_folder").catch((why) => say(String(why))));

await listen("agentsweep://view", (event) => render(event.payload));
render(await invoke("popover"));
