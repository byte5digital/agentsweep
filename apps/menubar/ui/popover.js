// The popover. It renders the view the app hands over and calls the app's
// commands; it decides nothing. Placeholder wording throughout.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const root = document.querySelector(".popover");
const sentence = document.getElementById("sentence");
const detail = document.getElementById("detail");
const lastCheck = document.getElementById("last-check");
const loginItems = document.getElementById("login-items");
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
  sentence.textContent = view.sentence;
  detail.textContent = view.detail;
  detail.hidden = view.detail === "";
  if (view.lastCheck) {
    lastCheck.textContent = `Last check: ${when(view.lastCheck)}`;
    lastCheck.hidden = false;
  } else {
    lastCheck.hidden = true;
  }
  loginItems.hidden = !view.loginItems;
  // When the daemon is unreachable the app shows Protection off and offers
  // nothing else (spec section 6.2).
  asking.hidden = view.protectionOff;
}

function say(line) {
  scanLine.textContent = line;
  scanLine.hidden = line === "";
}

loginItems.addEventListener("click", () => invoke("open_login_items"));
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
await listen("agentsweep://findings", (event) => {
  if (event.payload.scan.running) {
    say(event.payload.scan.line);
  }
});
render(await invoke("popover"));
