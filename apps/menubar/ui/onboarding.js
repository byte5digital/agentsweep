// The onboarding wizard. It renders the view the app hands over and calls
// the app's commands; the screens, Back and Next and the answers are decided
// in the app (spec section 8.3). Everything is written with textContent,
// never as markup.
//
// The Claude API key is read from its field once, when "I agree, turn it on"
// is pressed: the field is emptied at once and the key goes to the app,
// which holds it only until the daemon takes it. Nothing here stores it.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const steps = $("steps");
const back = $("back");
const next = $("next");
const error = $("error");

// The view the app sent last.
let current = null;

function text(id, value) {
  $(id).textContent = value ?? "";
}

function el(tag, className, value) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (value !== undefined && value !== null) {
    node.textContent = value;
  }
  return node;
}

function renderAgents(inventory) {
  const list = $("agents");
  list.replaceChildren();
  for (const found of inventory.agents) {
    const item = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = found.version ? `${found.name} ${found.version}` : found.name;
    const count = document.createElement("span");
    count.textContent = found.projects;
    item.append(name, count);
    if (found.notRead) {
      item.append(el("p", "muted", found.notRead));
    }
    list.append(item);
  }
  const none = $("none");
  none.hidden = !inventory.none;
  none.textContent = inventory.none ?? "";
  text("own-lists", inventory.ownLists);
}

// The Ollama confirmation: the model the engine answer names, loopback only.
function confirmOllama() {
  const asked = current.ai.ollama;
  if (asked === null) {
    return;
  }
  const dialog = $("ollama");
  dialog.querySelector(".question").textContent = asked.question;
  dialog.querySelector(".lines").replaceChildren(...asked.lines.map((line) => el("p", "", line)));
  $("ollama-ok").textContent = asked.ok;
  dialog.addEventListener(
    "close",
    () => {
      if (dialog.returnValue === "ok") {
        ask("onboarding_engine", { engine: "ollama", confirmed: true });
      }
    },
    { once: true },
  );
  dialog.returnValue = "";
  dialog.showModal();
}

// The Claude consent screen of the Settings pane: the table, the caps,
// Preview a request, the key field and "I agree, turn it on".
function openConsent() {
  const consent = current.ai.consent;
  const dialog = $("consent");
  dialog.querySelector(".title").textContent = consent.title;
  dialog.querySelector("tbody").replaceChildren(
    ...consent.rows.map((row) => {
      const tr = el("tr");
      tr.append(el("th", "", row.label), el("td", "", row.text));
      return tr;
    }),
  );
  $("consent-preview").textContent = consent.preview;
  $("consent-preview-text").hidden = true;
  dialog.querySelector(".key-label").textContent = consent.keyLabel;
  dialog.querySelector(".key-line").textContent = consent.keyLine;
  const field = $("consent-key");
  field.value = "";
  const agree = $("consent-agree");
  agree.textContent = consent.agree;
  const follow = () => {
    agree.disabled = field.value.trim() === "";
  };
  field.oninput = follow;
  follow();
  dialog.showModal();
}

async function agreeToClaude() {
  const field = $("consent-key");
  const typed = field.value.trim();
  // Emptied before anything else: the window keeps no copy of the key.
  field.value = "";
  $("consent").close();
  await ask("onboarding_claude", { key: typed === "" ? null : typed });
}

// A request needs the daemon, which runs only after screen 5; before that
// the screen says where to preview one.
async function showPreview() {
  const shown = $("consent-preview-text");
  try {
    const preview = await invoke("preview_request", { item: null });
    shown.textContent = [preview.about, ...preview.lines].join("\n");
  } catch (_) {
    shown.textContent = current.ai.previewLater;
  }
  shown.hidden = false;
}

function choose(card) {
  if (card.engine === "ollama") {
    confirmOllama();
  } else if (card.engine === "claude") {
    openConsent();
  } else {
    ask("onboarding_engine", { engine: card.engine });
  }
}

function renderCard(card) {
  const button = el("button", "card");
  button.type = "button";
  button.setAttribute("role", "radio");
  button.setAttribute("aria-checked", String(card.selected));
  button.disabled = !card.enabled;
  button.append(el("span", "label", card.title), el("span", "muted", card.leaves));
  if (card.reason !== null) {
    button.append(el("span", "muted", card.reason));
  }
  if (card.warning !== null) {
    button.append(el("span", "error", card.warning));
  }
  button.addEventListener("click", () => {
    const unconfirmed = card.engine === "ollama" && current.ai.needsConfirmation;
    if (!card.selected || unconfirmed || card.engine === "claude") {
      choose(card);
    }
  });
  return button;
}

function renderAi(ai) {
  text("ai-title", ai.title);
  $("ai-choices").replaceChildren(...ai.choices.map(renderCard));
  const others = $("ai-others-line");
  others.hidden = ai.othersLine === null;
  others.textContent = ai.othersLine ?? "";
  $("ai-others").replaceChildren(...ai.others.map(renderCard));
  text("ai-later", ai.later);
}

function renderBackground(background) {
  $("background-lines").replaceChildren(...background.lines.map((line) => el("p", "", line)));
  text("background-disclosure", background.disclosure);
  $("background-toggles").replaceChildren(
    ...background.toggles.map((toggle) => {
      const label = el("label");
      const box = el("input");
      box.type = "checkbox";
      box.checked = toggle.on;
      box.addEventListener("change", () =>
        ask("onboarding_toggle", { key: toggle.key, on: box.checked }),
      );
      label.append(box, " ", toggle.label);
      return label;
    }),
  );
  const place = $("protected");
  const protectedLine = background.protected;
  place.hidden = protectedLine === null;
  if (protectedLine !== null) {
    text("protected-line", protectedLine.line);
    const button = $("protected-button");
    button.textContent = protectedLine.button;
    button.disabled = protectedLine.sent !== null;
    const sent = $("protected-sent");
    sent.hidden = protectedLine.sent === null;
    sent.textContent = protectedLine.sent ?? "";
  }
}

function renderFirst(first) {
  text("first-title", first.title);
  const waiting = first.waiting !== undefined;
  $("first-waiting").hidden = !waiting;
  $("first-done").hidden = waiting;
  if (waiting) {
    text("first-waiting", first.waiting);
    return;
  }
  text("first-items", first.items);
  text("first-baseline", first.baseline);
  text("first-stopped-line", first.stoppedLine);
  $("first-stopped").replaceChildren(...first.stopped.map((title) => el("li", "", title)));
  text("first-result", first.result);
}

function render(view) {
  if (!view) {
    return;
  }
  current = view;
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
  renderAi(view.ai);
  renderBackground(view.background);
  renderFirst(view.first);
  back.hidden = !view.back;
  next.hidden = view.screen === "first" && view.first.waiting !== undefined;
  next.textContent =
    view.screen === "background"
      ? view.background.button
      : view.screen === "first"
        ? (view.first.button ?? "")
        : "Continue";
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
next.addEventListener("click", () => {
  // Ollama preselected needs its one confirmation before the wizard moves on.
  if (current && current.screen === "ai" && current.ai.needsConfirmation) {
    confirmOllama();
    return;
  }
  ask("onboarding_next");
});
for (const choice of document.querySelectorAll("input[name=posture]")) {
  choice.addEventListener("change", () => ask("onboarding_choose", { posture: choice.value }));
}
$("protected-button").addEventListener("click", () => ask("onboarding_look_there"));
$("consent-agree").addEventListener("click", agreeToClaude);
$("consent-preview").addEventListener("click", showPreview);
$("consent-cancel").addEventListener("click", () => $("consent").close());
// However the consent screen closes, the field is emptied.
$("consent").addEventListener("close", () => {
  $("consent-key").value = "";
});

// The engine look and the first check finished arrive without a command.
listen("agentsweep://onboarding", (event) => render(event.payload));

ask("onboarding");
