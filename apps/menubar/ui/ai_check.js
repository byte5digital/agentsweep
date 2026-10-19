// The AI check in the Settings pane (spec sections 4.4, 8.4 and 8.10): the
// four engine cards, the Ollama confirmation, the Claude consent screen with
// "Preview a request" and the key field, the cap-reached line, and under
// Advanced the Ollama address and, in the Developer Posture, the Claude
// model id. Every word and every state comes from the app's view; this
// module only renders it and invokes the app's commands. Everything is
// written with textContent, never as markup.
//
// The Claude API key is read from its field once, when "I agree, turn it on"
// is pressed: the field is emptied at once and the key goes to the app,
// which hands it to the daemon and keeps no copy. Nothing here stores it.

const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = text;
  }
  return node;
}

// The view the app sent last.
let current = null;

function answer(text) {
  $("ai-check-answer").textContent = text;
}

async function ask(command, args) {
  try {
    answer(await invoke(command, args));
    return true;
  } catch (why) {
    answer(String(why));
    return false;
  }
}

// Asks the daemon where the AI check stands, with whether Ollama runs and
// Apple's model is available. The Settings pane asks it when it opens.
export function lookAtAiCheck() {
  invoke("ai_check_look").catch((why) => answer(String(why)));
}

// The Ollama confirmation: the model the daemon reports, loopback only.
function confirmOllama() {
  const asked = current.ollama;
  if (asked === null) {
    return;
  }
  const dialog = $("ai-ollama");
  dialog.querySelector(".question").textContent = asked.question;
  dialog.querySelector(".lines").replaceChildren(...asked.lines.map((line) => el("p", "", line)));
  $("ai-ollama-ok").textContent = asked.ok;
  dialog.addEventListener(
    "close",
    () => {
      if (dialog.returnValue === "ok") {
        ask("change_engine", { change: { engine: "ollama", model: asked.model } });
      }
    },
    { once: true },
  );
  dialog.showModal();
}

// The Claude consent screen: the table, the caps, Preview a request, the
// key field and "I agree, turn it on", which stays disabled until a key is
// typed or one is already set.
function openConsent() {
  const consent = current.consent;
  const dialog = $("ai-consent");
  dialog.querySelector(".title").textContent = consent.title;
  const rows = consent.rows.map((row) => {
    const tr = el("tr");
    tr.append(el("th", "", row.label), el("td", "", row.text));
    return tr;
  });
  dialog.querySelector("tbody").replaceChildren(...rows);
  $("ai-consent-preview").textContent = consent.preview;
  $("ai-consent-preview-text").hidden = true;
  dialog.querySelector(".key-label").textContent = consent.keyLabel;
  dialog.querySelector(".key-line").textContent = consent.keyLine;
  const field = $("ai-consent-key");
  field.value = "";
  const set = current.key.set;
  field.hidden = set;
  dialog.querySelector(".key-set").textContent = set ? current.key.line : "";
  const agree = $("ai-consent-agree");
  agree.textContent = consent.agree;
  const follow = () => {
    agree.disabled = !set && field.value.trim() === "";
  };
  field.oninput = follow;
  follow();
  dialog.showModal();
}

async function agreeToClaude() {
  const field = $("ai-consent-key");
  const typed = field.value.trim();
  // Emptied before anything else: the window keeps no copy of the key.
  field.value = "";
  $("ai-consent").close();
  await ask("turn_on_claude", { key: typed === "" ? null : typed });
}

async function showPreview() {
  const shown = $("ai-consent-preview-text");
  try {
    const preview = await invoke("preview_request", { item: null });
    const parts = [preview.about, ...preview.lines];
    if (preview.system !== null) {
      parts.push("", preview.system, "", preview.user);
    }
    shown.textContent = parts.join("\n");
  } catch (why) {
    shown.textContent = String(why);
  }
  shown.hidden = false;
}

function choose(card) {
  if (card.ask === "ollama") {
    confirmOllama();
  } else if (card.ask === "claude") {
    openConsent();
  } else {
    ask("change_engine", { change: { engine: card.engine } });
  }
}

function renderCard(card) {
  const button = el("button", "card");
  button.type = "button";
  button.setAttribute("role", "radio");
  button.setAttribute("aria-checked", String(card.selected));
  button.disabled = !card.enabled;
  button.append(el("span", "label", card.title), el("span", "muted leaves", card.leaves));
  if (card.reason !== null) {
    button.append(el("span", "muted reason", card.reason));
  }
  if (card.warning !== null) {
    button.append(el("span", "warning", card.warning));
  }
  button.addEventListener("click", () => {
    if (!card.selected || card.ask === "claude") {
      choose(card);
    }
  });
  return button;
}

function field(entry, key) {
  const row = el("label", "dir");
  row.append(el("span", "label", entry.label));
  const input = el("input");
  input.type = "text";
  input.value = entry.value;
  input.placeholder = entry.default;
  input.disabled = !current.available;
  input.addEventListener("change", () => ask("change_engine", { change: { [key]: input.value } }));
  row.append(input, el("span", "muted", entry.line));
  return row;
}

// Renders the AI check from the app's view, or hides it before the daemon
// answered.
export function renderAiCheck(view) {
  current = view;
  const place = $("settings-ai-check");
  const advanced = $("settings-advanced-ai");
  place.hidden = view === null;
  advanced.hidden = view === null;
  if (view === null) {
    return;
  }
  place.querySelector("h3").textContent = view.title;
  place.querySelector(".intro").textContent = view.intro;
  place.querySelector(".cards").replaceChildren(...view.cards.map(renderCard));
  place.querySelector(".lines").replaceChildren(...view.lines.map((line) => el("p", "muted", line)));
  const key = place.querySelector(".key");
  key.hidden = !view.key.set;
  if (view.key.set) {
    key.querySelector(".key-set").textContent = view.key.line;
    key.querySelector(".remove-line").textContent = view.key.removeLine;
    const remove = key.querySelector(".remove");
    remove.textContent = view.key.remove;
    remove.disabled = !view.available;
  }
  const fields = [field(view.advanced.ollamaAddress, "ollama_address")];
  if (view.advanced.claudeModel !== null) {
    fields.push(field(view.advanced.claudeModel, "claude_model"));
  }
  advanced.replaceChildren(...fields);
}

$("settings-ai-check")
  .querySelector(".remove")
  .addEventListener("click", () => ask("remove_claude_key", {}));
$("ai-consent-agree").addEventListener("click", agreeToClaude);
$("ai-consent-preview").addEventListener("click", showPreview);
$("ai-consent-cancel").addEventListener("click", () => $("ai-consent").close());
// However the screen closes, the field is emptied.
$("ai-consent").addEventListener("close", () => {
  $("ai-consent-key").value = "";
});
