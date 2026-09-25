// The popover. It renders the view the app hands over and calls three
// commands; it decides nothing. Placeholder wording throughout.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const root = document.querySelector(".popover");
const sentence = document.getElementById("sentence");
const detail = document.getElementById("detail");
const lastCheck = document.getElementById("last-check");
const loginItems = document.getElementById("login-items");
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
}

loginItems.addEventListener("click", () => invoke("open_login_items"));
quit.addEventListener("click", () => invoke("quit"));

await listen("agentsweep://view", (event) => render(event.payload));
render(await invoke("popover"));
