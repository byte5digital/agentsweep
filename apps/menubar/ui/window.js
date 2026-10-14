// The Findings window. It renders the frame the app hands over (the sidebar
// with its counts, one pane per entry, the open Findings in the two Finding
// panes as a list beside the selected Finding) and the Folder Scan, and
// invokes the app's commands; every decision about what is listed, counted
// and offered was made by the daemon and the app. Which pane and which
// Finding are selected is the window's own. Everything is written with
// textContent, never as markup. Placeholder wording throughout.

import { takePosture } from "./posture.js";

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

// The confirmation dialog: answers true when the user confirmed.
function confirmWith(asked, label) {
  const dialog = $("confirm");
  $("confirm-question").textContent = asked.question;
  $("confirm-sessions").textContent = asked.sessions;
  $("confirm-sessions").hidden = asked.sessions === "";
  $("confirm-project").textContent = asked.project;
  $("confirm-project").hidden = asked.project === "";
  $("confirm-ok").textContent = label;
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok"), { once: true });
    dialog.showModal();
  });
}

// What an action answered: the daemon's sentence, whether Agent sessions
// appear to be running, and the lines the command line interface prints.
function showResult(result) {
  $("notice").hidden = false;
  $("notice-message").textContent = result.message;
  $("notice-sessions").textContent = result.sessions;
  $("notice-sessions").hidden = result.sessions === "";
  $("notice-lines").textContent = result.details.join("\n");
  $("notice-details").hidden = result.details.length === 0;
  const choices = $("notice-choices");
  choices.replaceChildren();
  if (result.conflict) {
    for (const [label, conflict] of [
      ["Replace the new file", "replace"],
      ["Restore beside it", "beside"],
    ]) {
      const button = el("button", "", label);
      button.type = "button";
      button.dataset.action = "restore";
      button.addEventListener("click", () =>
        run({ command: "restore", target: result.target, conflict, label }),
      );
      choices.append(button);
    }
  }
  disableActions();
}

function showFailure(why) {
  showResult({
    message: String(why),
    sessions: "",
    details: [],
    conflict: false,
    target: "",
  });
}

async function run(action, card) {
  try {
    if (action.confirm === "quarantine") {
      const asked = await invoke("sessions", { target: action.target });
      if (!(await confirmWith(asked, action.label))) {
        return;
      }
    } else if (action.confirm === "trust" && card) {
      if (!(await confirmWith(card.trustConfirm, action.label))) {
        return;
      }
    }
    const result = await invoke(action.command, {
      target: action.target,
      conflict: action.conflict,
    });
    showResult(result);
  } catch (why) {
    showFailure(why);
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
    const actions = el("div", "actions");
    for (const action of card.actions) {
      const button = el("button", "", action.label);
      button.type = "button";
      button.dataset.action = action.command;
      button.addEventListener("click", () => run(action, card));
      actions.append(button);
    }
    node.append(actions);
  }
  return node;
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
  row.append(el("span", "title", `${card.kind} · ${card.name}`));
  row.append(el("span", "chip", card.severity));
  if (card.id === selectedFinding[id]) {
    row.setAttribute("aria-current", "true");
  }
  row.addEventListener("click", () => {
    selectedFinding[id] = card.id;
    render(view);
  });
  return row;
}

function renderFindingPane(id, cards, loaded) {
  const node = pane(id);
  if (!cards.some((card) => card.id === selectedFinding[id])) {
    selectedFinding[id] = cards.length > 0 ? cards[0].id : null;
  }
  node.querySelector(".empty").hidden = !loaded || cards.length > 0;
  node.querySelector(".split").hidden = cards.length === 0;
  node.querySelector(".list").replaceChildren(...cards.map((card) => renderRow(id, card)));
  const selected = cards.find((card) => card.id === selectedFinding[id]);
  node.querySelector(".detail").replaceChildren(...(selected ? [renderCard(selected)] : []));
}

function render(list) {
  view = list;
  takePosture(list.posture);
  $("off").hidden = list.off === null;
  $("off").textContent = list.off === null ? "" : `Protection is off: ${list.off}.`;
  // With Protection off the window offers nothing (spec section 6.2).
  $("scan").hidden = list.off !== null;
  $("scan-line").textContent = list.scan.line;
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

$("scan-now").addEventListener("click", async () => {
  try {
    $("scan-line").textContent = await invoke("scan_now");
  } catch (why) {
    showFailure(why);
  }
});
$("scan-folder").addEventListener("click", () => invoke("scan_folder").catch(showFailure));

await listen("agentsweep://findings", (event) => render(event.payload));
await listen("agentsweep://folder", (event) => renderFolder(event.payload));
renderFolder(await invoke("folder"));
render(await invoke("findings"));
