// The Findings window. It renders the list and the Folder Scan the app hands
// over and invokes the app's commands; every decision about what is listed
// and what is offered was made by the daemon and the app. Everything is
// written with textContent, never as markup. Placeholder wording throughout.

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

function render(list) {
  $("off").hidden = list.off === null;
  $("off").textContent = list.off === null ? "" : `Protection is off: ${list.off}.`;
  // With Protection off the window offers nothing (spec section 6.2).
  $("scan").hidden = list.off !== null;
  $("scan-line").textContent = list.scan.line;
  actionsWait = list.actionsWait;
  $("actions-wait").hidden = actionsWait === null;
  $("actions-wait").textContent = actionsWait === null ? "" : actionsWait;
  $("counts").textContent = `${list.counts.threats} Threat, ${list.counts.exposures} Exposure`;
  $("open").replaceChildren(...list.open.map(renderCard));
  $("empty").hidden = !list.loaded || list.open.length > 0;
  $("decided").replaceChildren(...list.decided.map(renderCard));
  $("decided-section").hidden = list.decided.length === 0;
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
    for (const id of ["folder-summary", "folder-ambiguous", "folder-recorded"]) {
      $(id).textContent = "";
    }
    $("folder-cards").replaceChildren();
    return;
  }
  $("folder-verdict").textContent = view.verdict;
  $("folder-summary").textContent = view.summary;
  $("folder-ambiguous").textContent = view.ambiguous;
  $("folder-recorded").textContent = view.recorded;
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
