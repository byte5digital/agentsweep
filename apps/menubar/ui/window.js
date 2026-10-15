// The Findings window. It renders the frame the app hands over (the sidebar
// with its counts, one pane per entry, the Overview, the open Findings in the
// two Finding panes as a list beside the selected Finding) and the Folder
// Scan, and
// invokes the app's commands; every decision about what is listed, counted
// and offered was made by the daemon and the app. Which pane and which
// Finding are selected is the window's own. Everything is written with
// textContent, never as markup. In the Simple Posture a Finding reads as the
// app worded it (spec section 8.4); the Developer Posture's rendering is
// still the placeholder.

import { isDeveloper, takePosture } from "./posture.js";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

// Why the actions cannot be pressed right now, or null when they can: while a
// Scan runs every action waits for it (the app's list says so).
let actionsWait = null;

// Every action button, the Restore conflict choices included, follows it.
function disableActions() {
  for (const button of document.querySelectorAll("button[data-action]")) {
    button.disabled = actionsWait !== null;
  }
}

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

// A confirmation the app worded (the question, the lines under it and what
// the confirming button says): answers true when the user confirmed.
function confirmWith(asked) {
  const dialog = $("confirm");
  $("confirm-question").textContent = asked.question;
  $("confirm-lines").replaceChildren(...asked.lines.map((line) => el("p", "", line)));
  $("confirm-ok").textContent = asked.ok;
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok"), { once: true });
    dialog.showModal();
  });
}

// The Restore conflict dialog: the daemon's sentence and the two choices
// the app sent with it, each of which sends its own Restore. Shown only when
// the daemon answered a Restore with a conflict.
function askConflict(result, card) {
  const dialog = $("conflict");
  $("conflict-message").textContent = result.message;
  const buttons = result.choices.map((choice) => {
    const button = el("button", "", choice.label);
    button.type = "button";
    button.dataset.action = choice.command;
    button.addEventListener("click", () => {
      dialog.close();
      run(choice, card);
    });
    return button;
  });
  $("conflict-choices").replaceChildren(...buttons);
  disableActions();
  dialog.showModal();
}

// The last action's answer and the Finding it belongs to. It shows beside
// that Finding, in its detail pane, and stays there after the Finding left
// the pane (a Quarantine moves it out of Needs your decision) until another
// Finding is selected. The top of the window carries nothing.
let answer = null;

// The title a Finding shows in the Posture in force.
function titleOf(card) {
  return isDeveloper() ? `${card.kind} · ${card.name}` : card.simple.title;
}

// Keeps an action's answer for the Finding it was given on, or for the
// Finding selected in the pane in sight when it names none.
function showResult(result, card) {
  const finding = card ?? selectedCard();
  if (!finding) {
    $("scan-line").textContent = result.message;
    return;
  }
  answer = { pane: paneOf(finding), id: finding.id, title: titleOf(finding), result };
  selectedFinding[answer.pane] = finding.id;
  if (view) {
    render(view);
  }
}

function showFailure(why, card) {
  showResult({ message: String(why), lines: [], details: [], choices: [], conflict: false }, card);
}

// One answer as the detail pane shows it: the daemon's sentence, the lines
// under it (after a Quarantine, its confirmation), and the Receipt lines
// under Details.
function renderAnswer(result) {
  const node = el("section", "answer");
  node.setAttribute("role", "status");
  node.append(el("p", "message", result.message));
  for (const line of result.lines ?? []) {
    node.append(el("p", "muted", line));
  }
  const lines = result.details ?? [];
  if (lines.length > 0) {
    const details = el("details");
    details.append(el("summary", "", "Details"), el("pre", "", lines.join("\n")));
    node.append(details);
  }
  return node;
}

async function run(action, card) {
  try {
    const asked = {
      trust: card?.trustConfirm,
      "restore-trust": card?.restoreConfirm,
    }[action.confirm];
    if (asked && !(await confirmWith(asked))) {
      return;
    }
    const result = await invoke(action.command, {
      target: action.target,
      conflict: action.conflict,
    });
    showResult(result, card);
    if (result.conflict) {
      askConflict(result, card);
    }
  } catch (why) {
    showFailure(why, card);
  }
}

function renderCard(card) {
  const node = el("article", "card");
  node.dataset.category = card.category;
  node.append(el("p", "title", `${card.kind} · ${card.name}`));
  const chips = el("div", "chips");
  for (const chip of [card.severity, card.tier, card.category, card.probation, card.source, card.state]) {
    if (chip) {
      chips.append(el("span", "chip", chip));
    }
  }
  node.append(chips);
  if (card.plain) {
    node.append(el("p", "", card.plain));
  }
  if (card.heuristics && card.heuristics.length > 0) {
    const list = el("ul", "muted");
    for (const line of card.heuristics) {
      list.append(el("li", "", line));
    }
    node.append(list);
  }
  if (card.drift) {
    node.append(el("p", "muted", card.drift));
  }
  if (card.note) {
    node.append(el("p", "muted", card.note));
  }
  node.append(el("p", "id", card.itemId));
  node.append(el("p", "id", `id ${card.id}`));
  if (card.receiptId) {
    node.append(el("p", "id", `receipt ${card.receiptId}`));
  }
  if (card.actions.length > 0) {
    node.append(renderActions(card, card.actions));
  }
  return node;
}

// The Findings whose technical details are open in the Simple Posture.
const detailsOpen = new Set();

// The technical table of one Finding: the same rows the Developer Posture
// shows (spec section 8.2), and under it the buttons the Simple Posture
// keeps behind Show technical details (Trust on a Drift question).
function renderTechnical(card) {
  const shown = document.createDocumentFragment();
  const table = el("table", "technical");
  for (const row of card.technical) {
    const line = el("tr");
    line.append(el("th", "", row.label), el("td", "", row.value));
    table.append(line);
  }
  shown.append(table);
  const behind = (card.actions ?? []).filter((action) => action.technical);
  if (behind.length > 0) {
    shown.append(renderActions(card, behind));
  }
  return shown;
}

// The buttons of one Finding: those the Posture shows in sight, or the ones
// given.
function renderActions(card, actions = card.actions.filter((action) => !action.technical)) {
  const node = el("div", "actions");
  for (const action of actions) {
    const button = el("button", "", action.label);
    button.type = "button";
    button.dataset.action = action.command;
    button.addEventListener("click", () => run(action, card));
    node.append(button);
  }
  return node;
}

// One Finding in the Simple Posture: the verdict title, the Severity word on
// its chip, the body in its fixed order, the actions, and the technical
// details one click away. No id, path, hash or Score is rendered here.
function renderSimpleCard(card) {
  const simple = card.simple;
  const node = el("article", "card");
  node.dataset.category = card.category;
  node.append(el("p", "title", simple.title));
  const chips = el("div", "chips");
  chips.append(el("span", `chip ${simple.chip}`, simple.severity));
  node.append(chips);
  let list = null;
  for (const line of simple.lines) {
    if (line.part === "heuristic") {
      if (list === null) {
        list = el("ul", "heuristics");
        node.append(list);
      }
      list.append(el("li", "", line.text));
      continue;
    }
    const muted = ["also", "project", "drift"].includes(line.part);
    node.append(el("p", muted ? "muted" : "", line.text));
  }
  const actions = renderActions(card);
  if (simple.admin) {
    const copy = el("button", "", "Copy a message for your admin");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        showResult({
          message: await invoke("copy_for_admin", { target: card.id }),
          sessions: "",
          details: [],
          conflict: false,
          target: "",
        });
      } catch (why) {
        showFailure(why);
      }
    });
    actions.append(copy);
  }
  if (actions.childElementCount > 0) {
    node.append(actions);
  }
  const open = detailsOpen.has(card.id);
  const toggle = el("button", "link", open ? "Hide technical details" : "Show technical details");
  toggle.type = "button";
  toggle.setAttribute("aria-expanded", String(open));
  toggle.addEventListener("click", () => {
    if (detailsOpen.has(card.id)) {
      detailsOpen.delete(card.id);
    } else {
      detailsOpen.add(card.id);
    }
    render(view);
  });
  node.append(toggle);
  if (open) {
    node.append(renderTechnical(card));
  }
  return node;
}

// A Finding of a Finding pane, in the Posture in force.
function renderFinding(card) {
  return isDeveloper() ? renderCard(card) : renderSimpleCard(card);
}

// The two panes that list Findings: a list beside the selected Finding.
const FINDING_PANES = ["threats", "exposures"];

// The view the app sent last, rendered again when the selection moves.
let view = null;
// The pane in sight, and the Finding selected in each Finding pane.
let selectedPane = "overview";
const selectedFinding = { threats: null, exposures: null };

function pane(id) {
  return document.querySelector(`.pane[data-pane="${id}"]`);
}

function select(id) {
  selectedPane = id;
  if (view) {
    render(view);
  }
}

function renderSidebar(entries) {
  const buttons = entries.map((entry) => {
    const button = el("button", "entry");
    button.type = "button";
    button.dataset.pane = entry.pane;
    button.append(el("span", "label", entry.label));
    if (entry.count !== null) {
      button.append(el("span", "count", String(entry.count)));
    }
    if (entry.pane === selectedPane) {
      button.setAttribute("aria-current", "page");
    }
    button.addEventListener("click", () => select(entry.pane));
    return button;
  });
  $("sidebar").replaceChildren(...buttons);
  for (const entry of entries) {
    pane(entry.pane).querySelector(".pane-title").textContent = entry.label;
    pane(entry.pane).hidden = entry.pane !== selectedPane;
  }
}

function renderRow(id, card) {
  const row = el("button", "row");
  row.type = "button";
  row.setAttribute("role", "listitem");
  row.dataset.category = card.category;
  if (isDeveloper()) {
    row.append(el("span", "title", `${card.kind} · ${card.name}`));
    row.append(el("span", "chip", card.severity));
  } else {
    row.append(el("span", "title", card.simple.title));
    row.append(el("span", `chip ${card.simple.chip}`, card.simple.severity));
  }
  if (card.id === selectedFinding[id]) {
    row.setAttribute("aria-current", "true");
  }
  row.addEventListener("click", () => {
    selectedFinding[id] = card.id;
    render(view);
  });
  return row;
}

// The pane a Finding is listed in.
function paneOf(card) {
  return card.category === "exposure" ? "exposures" : "threats";
}

// The Finding selected in the pane in sight, if that pane lists Findings.
function selectedCard() {
  if (!view || !FINDING_PANES.includes(selectedPane)) {
    return null;
  }
  return view.panes[selectedPane].find((card) => card.id === selectedFinding[selectedPane]) ?? null;
}

function renderFindingPane(id, cards, loaded) {
  const node = pane(id);
  // An answer stays beside its Finding, even once the Finding left the pane.
  const kept = answer !== null && answer.pane === id && answer.id === selectedFinding[id];
  if (!kept && !cards.some((card) => card.id === selectedFinding[id])) {
    selectedFinding[id] = cards.length > 0 ? cards[0].id : null;
  }
  node.querySelector(".empty").hidden = !loaded || cards.length > 0 || kept;
  node.querySelector(".split").hidden = cards.length === 0 && !kept;
  node.querySelector(".list").replaceChildren(...cards.map((card) => renderRow(id, card)));
  const selected = cards.find((card) => card.id === selectedFinding[id]);
  const detail = [];
  if (selected) {
    detail.push(renderFinding(selected));
  } else if (kept) {
    detail.push(el("p", "title", answer.title));
  }
  if (kept) {
    detail.push(renderAnswer(answer.result));
  }
  node.querySelector(".detail").replaceChildren(...detail);
}

// A moment in local time, as the popover writes it.
function when(text) {
  const moment = new Date(text);
  if (Number.isNaN(moment.getTime())) {
    return text;
  }
  return moment.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

// What "Scan now" answered, shown until the stream says more.
let scanAnswer = "";

// The Overview pane (spec section 8.1). With Protection off it shows the
// sentence alone and offers neither Scan action (spec section 6.2).
function renderOverview(overview) {
  $("overview-sentence").textContent = overview.sentence;
  $("overview-body").hidden = overview.off;
  $("overview-scan").hidden = !overview.actions;
  const agents = overview.agents.map((agent) => {
    const item = el("li", "", agent.line);
    item.dataset.agent = agent.agent;
    item.dataset.installed = String(agent.installed);
    return item;
  });
  $("overview-agents").replaceChildren(...agents);
  $("overview-last-check").textContent = overview.lastCheck
    ? `Last check: ${when(overview.lastCheck)}`
    : "Nothing checked yet.";
  $("overview-rules").textContent = overview.rulesUpdated ?? "";
  $("overview-rules").hidden = overview.rulesUpdated === null;
  if (overview.scan.running) {
    scanAnswer = "";
  }
  $("scan-line").textContent = overview.scan.running ? overview.scan.progress : scanAnswer;
  $("overview-summary").textContent = overview.summary ?? "";
  $("overview-summary").hidden = overview.summary === null;
}

function render(list) {
  view = list;
  takePosture(list.posture);
  $("off").hidden = list.off === null;
  $("off").textContent = list.off === null ? "" : `Protection is off: ${list.off}.`;
  renderOverview(list.overview);
  actionsWait = list.actionsWait;
  $("actions-wait").hidden = actionsWait === null;
  $("actions-wait").textContent = actionsWait === null ? "" : actionsWait;
  renderSidebar(list.sidebar);
  for (const id of FINDING_PANES) {
    renderFindingPane(id, list.panes[id], list.loaded);
  }
  disableActions();
}

function renderFolder(view) {
  const section = $("folder");
  if (!view) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  section.dataset.safe = view.state === "done" ? String(view.safe) : "";
  $("folder-root").textContent = view.root;
  if (view.state !== "done") {
    $("folder-verdict").textContent = view.line;
    for (const id of ["folder-summary", "folder-ambiguous", "folder-recorded", "folder-pack"]) {
      $(id).textContent = "";
    }
    $("folder-cards").replaceChildren();
    return;
  }
  $("folder-verdict").textContent = view.verdict;
  $("folder-summary").textContent = view.summary;
  $("folder-ambiguous").textContent = view.ambiguous;
  $("folder-recorded").textContent = view.recorded;
  $("folder-pack").textContent = view.rulePack;
  $("folder-cards").replaceChildren(...view.findings.map(renderCard));
}

// The same request the popover's Scan now sends; the progress and the last
// Scan follow from the stream.
$("scan-now").addEventListener("click", async () => {
  try {
    scanAnswer = await invoke("scan_now");
    $("scan-line").textContent = scanAnswer;
  } catch (why) {
    $("scan-line").textContent = String(why);
  }
});
$("scan-folder").addEventListener("click", () =>
  invoke("scan_folder").catch((why) => {
    $("scan-line").textContent = String(why);
  }),
);

await listen("agentsweep://findings", (event) => render(event.payload));
await listen("agentsweep://folder", (event) => renderFolder(event.payload));
renderFolder(await invoke("folder"));
render(await invoke("findings"));
