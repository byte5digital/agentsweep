// The onboarding wizard. It renders the view the app hands over and calls
// the app's commands; the screens, Back and Next and the answers are decided
// in the app (spec section 8.3).

const { invoke } = window.__TAURI__.core;

const steps = document.getElementById("steps");
const back = document.getElementById("back");
const next = document.getElementById("next");
const error = document.getElementById("error");

function text(id, value) {
  document.getElementById(id).textContent = value ?? "";
}

function renderAgents(inventory) {
  const list = document.getElementById("agents");
  list.replaceChildren();
  for (const found of inventory.agents) {
    const item = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = found.version ? `${found.name} ${found.version}` : found.name;
    const count = document.createElement("span");
    count.textContent = found.projects;
    item.append(name, count);
    if (found.notRead) {
      const line = document.createElement("p");
      line.className = "muted";
      line.textContent = found.notRead;
      item.append(line);
    }
    list.append(item);
  }
  const none = document.getElementById("none");
  none.hidden = !inventory.none;
  none.textContent = inventory.none ?? "";
  text("own-lists", inventory.ownLists);
}

function render(view) {
  if (!view) {
    return;
  }
  for (const section of document.querySelectorAll("section[data-screen]")) {
    section.hidden = section.dataset.screen !== view.screen;
  }
  steps.textContent = `Step ${view.step} of ${view.steps}`;
  text("welcome-what", view.welcome[0]);
  text("welcome-promise", view.welcome[1]);
  renderAgents(view.inventory);
  text("detail-question", view.detail.question);
  text("simple", view.detail.simple);
  text("developer", view.detail.developer);
  text("detail-later", view.detail.later);
  for (const choice of document.querySelectorAll("input[name=posture]")) {
    choice.checked = choice.value === view.detail.chosen;
  }
  text("background-line", view.background.line);
  back.hidden = !view.back;
  next.textContent = view.screen === "background" ? view.background.button : "Continue";
  error.hidden = true;
}

async function ask(command, args) {
  try {
    render(await invoke(command, args));
  } catch (why) {
    error.textContent = String(why);
    error.hidden = false;
  }
}

back.addEventListener("click", () => ask("onboarding_back"));
next.addEventListener("click", () => ask("onboarding_next"));
for (const choice of document.querySelectorAll("input[name=posture]")) {
  choice.addEventListener("change", () => ask("onboarding_choose", { posture: choice.value }));
}

ask("onboarding");
