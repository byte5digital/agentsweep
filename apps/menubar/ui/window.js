// The Findings window. It renders the frame the app hands over (the sidebar
// with its counts, one pane per entry, the Overview, the open Findings in the
// two Finding panes as a list beside the selected Finding) and the Scan a
// folder dialog, and invokes the app's commands; every decision about what
// is listed, counted and offered was made by the daemon and the app. Which
// pane and which Finding are selected is the window's own. Everything is
// written with textContent, never as markup. In the Simple Posture a Finding reads as the
// app worded it (spec section 8.4); in the Developer Posture it reads as
// `<Kind> · <name>` with its chips, the same body lines and the technical
// table shown always, and the Threat Findings pane lists the Ambiguous Items
// beneath the Findings (spec sections 4.3 and 8.2).

import { renderBanner } from "./banner.js";
import { isDeveloper, onPostureChange, takePosture } from "./posture.js";
import { lookAtAiCheck, renderAiCheck } from "./ai_check.js";

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
  if (card.trustedTitle) {
    return card.trustedTitle;
  }
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
      purge: card?.purgeConfirm,
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

// A Folder Scan's Finding in the Posture's wording: the Simple verdict title
// with its Severity word and the technical details one click away, or the
// Developer heading with its chips and the technical table shown always. It
// recorded nothing, so it offers no action.
function renderFolderCard(card) {
  const node = el("article", "card");
  node.dataset.category = card.category;
  if (isDeveloper()) {
    node.append(el("p", "title", card.developer.title));
    const chips = el("div", "chips");
    for (const chip of card.developer.chips) {
      const span = el("span", "chip", chip.text);
      span.dataset.fact = chip.fact;
      chips.append(span);
    }
    node.append(chips);
    renderLines(node, card.simple.lines);
    node.append(renderTechnical(card));
    return node;
  }
  node.append(el("p", "title", card.simple.title));
  const chips = el("div", "chips");
  chips.append(el("span", `chip ${card.simple.chip}`, card.simple.severity));
  node.append(chips);
  renderLines(node, card.simple.lines);
  const key = `folder ${card.id}`;
  node.append(renderToggle(key, () => renderFolder(folderView)));
  if (detailsOpen.has(key)) {
    node.append(renderTechnical(card));
  }
  return node;
}

// The Findings and Ambiguous Items whose technical details are open.
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
  renderLines(node, simple.lines);
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
  const howTo = document.createDocumentFragment();
  addHowTo(card, howTo, actions);
  if (actions.childElementCount > 0) {
    node.append(actions);
  }
  node.append(howTo);
  node.append(renderToggle(card.id));
  if (detailsOpen.has(card.id)) {
    node.append(renderTechnical(card));
  }
  return node;
}

// The body lines the app worded, in their fixed order (spec section 8.4).
function renderLines(node, lines) {
  let list = null;
  for (const line of lines) {
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
}

// One Finding in the Developer Posture: `<Kind> · <name>` with chips for
// Severity, Tier, category, Probation, Scope and Activation, the body lines,
// the technical table shown always, the actions and, on a quarantined Item
// with a payload, Reveal in Finder.
function renderDeveloperCard(card) {
  const developer = card.developer;
  const node = el("article", "card");
  node.dataset.category = card.category;
  node.append(el("p", "title", developer.title));
  const chips = el("div", "chips");
  for (const chip of developer.chips) {
    const span = el("span", "chip", chip.text);
    span.dataset.fact = chip.fact;
    chips.append(span);
  }
  node.append(chips);
  renderLines(node, card.simple.lines);
  node.append(renderTechnical(card));
  const actions = renderActions(card);
  if (card.reveal) {
    const reveal = el("button", "", "Reveal in Finder");
    reveal.type = "button";
    reveal.addEventListener("click", async () => {
      try {
        showResult({
          message: await invoke("reveal_in_finder", { target: card.id }),
          sessions: "",
          details: [],
          conflict: false,
          target: "",
        });
      } catch (why) {
        showFailure(why);
      }
    });
    actions.append(reveal);
  }
  const howTo = document.createDocumentFragment();
  addHowTo(card, howTo, actions);
  if (actions.childElementCount > 0) {
    node.append(actions);
  }
  node.append(howTo);
  return node;
}

// The Exposure Findings whose how-to is open, by id.
const howToOpen = new Set();

// Show me how to fix this on an Exposure, put first among its buttons, and
// when open the how-to under them: the steps the Rule Pack carries, the file
// by the name or path the app chose for the Posture, and Open the file,
// which names only the Finding (spec section 8.5).
function addHowTo(card, node, actions) {
  const howTo = card.howTo;
  if (!howTo) {
    return;
  }
  const open = howToOpen.has(card.id);
  const show = el("button", "", howTo.label);
  show.type = "button";
  show.setAttribute("aria-expanded", String(open));
  show.addEventListener("click", () => {
    if (howToOpen.has(card.id)) {
      howToOpen.delete(card.id);
    } else {
      howToOpen.add(card.id);
    }
    render(view);
  });
  actions.prepend(show);
  if (!open) {
    return;
  }
  const section = el("section", "how-to");
  section.append(el("p", "", howTo.steps));
  section.append(el("p", "muted", `The file: ${howTo.file}`));
  const file = el("button", "", howTo.open);
  file.type = "button";
  file.addEventListener("click", async () => {
    try {
      showResult(
        {
          message: await invoke("open_the_file", { target: card.id }),
          lines: [],
          details: [],
          choices: [],
          conflict: false,
        },
        card,
      );
    } catch (why) {
      showFailure(why, card);
    }
  });
  const buttons = el("div", "actions");
  buttons.append(file);
  section.append(buttons);
  node.append(section);
}

// The Show technical details toggle of one Finding or Ambiguous Item.
function renderToggle(id, again = () => render(view)) {
  const open = detailsOpen.has(id);
  const toggle = el("button", "link", open ? "Hide technical details" : "Show technical details");
  toggle.type = "button";
  toggle.setAttribute("aria-expanded", String(open));
  toggle.addEventListener("click", () => {
    if (detailsOpen.has(id)) {
      detailsOpen.delete(id);
    } else {
      detailsOpen.add(id);
    }
    again();
  });
  return toggle;
}

// One Ambiguous Item, in the Developer Posture only: its title, its Score,
// its Heuristic lines and its technical details. It is not a Finding, so it
// offers no action.
function renderAmbiguous(item) {
  const node = el("article", "card ambiguous");
  node.append(el("p", "title", item.title));
  node.append(el("p", "muted", item.score));
  const list = el("ul", "heuristics");
  for (const line of item.lines) {
    list.append(el("li", "", line));
  }
  node.append(list);
  const key = `ambiguous:${item.id}`;
  node.append(renderToggle(key));
  if (detailsOpen.has(key)) {
    node.append(renderTechnical(item));
  }
  return node;
}

// The Ambiguous Items beneath the Threat Findings. The app sends them in the
// Developer Posture only; the Simple Posture never shows one (spec 8.4).
function renderAmbiguousList(items) {
  const section = pane("threats").querySelector(".ambiguous-items");
  const shown = isDeveloper() && Array.isArray(items) && items.length > 0;
  section.hidden = !shown;
  section.querySelector(".list").replaceChildren(...(shown ? items.map(renderAmbiguous) : []));
}

// A Finding of a Finding pane, in the Posture in force.
function renderFinding(card) {
  return isDeveloper() ? renderDeveloperCard(card) : renderSimpleCard(card);
}

// The panes that list a list beside the selected entry: the two Finding
// panes and the Quarantine pane.
const FINDING_PANES = ["threats", "exposures", "quarantine"];

// The view the app sent last, rendered again when the selection moves.
let view = null;
// The pane in sight, and the Finding selected in each Finding pane.
let selectedPane = "overview";
const selectedFinding = { threats: null, exposures: null, quarantine: null };

function pane(id) {
  return document.querySelector(`.pane[data-pane="${id}"]`);
}

function select(id) {
  if (id === "settings" && selectedPane !== "settings") {
    lookAtAiCheck();
  }
  selectedPane = id;
  activityFocus = null;
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
    row.append(el("span", "title", card.developer.title));
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

// The pane a Finding is listed in: what is stopped or trusted is in the
// Quarantine pane.
function paneOf(card) {
  if (card.state === "stopped" || card.state === "trusted") {
    return "quarantine";
  }
  return card.category === "exposure" ? "exposures" : "threats";
}

// One entry of the Quarantine pane: the Finding's card with, under its
// chips, who stopped it and when, the withdrawn Rule line, the fixed version
// line and, in the Developer Posture only, the Receipt id.
function renderQuarantineEntry(card) {
  const node = renderFinding(card);
  const lines = el("div", "quarantine-lines");
  const stopped = card.stopped;
  lines.append(el("p", "", stopped.at ? `${stopped.line} on ${when(stopped.at)}.` : `${stopped.line}.`));
  if (card.withdrawn) {
    lines.append(el("p", "withdrawn", card.withdrawn));
  }
  if (card.fixedLine) {
    lines.append(el("p", "", card.fixedLine));
  }
  if (isDeveloper() && card.receiptId) {
    lines.append(el("p", "id", `Receipt ${card.receiptId}`));
  }
  node.querySelector(".chips").after(lines);
  return node;
}

// The Trusted section at the foot of the Quarantine pane, each with Stop
// trusting this in both Postures. Its answer shows in the pane's detail.
function renderTrusted(entries) {
  const section = pane("quarantine").querySelector(".trusted");
  section.hidden = entries.length === 0;
  const rows = entries.map((entry) => {
    const row = el("div", "trusted-entry");
    row.setAttribute("role", "listitem");
    row.append(el("span", "title", entry.title));
    const button = el("button", "", entry.action.label);
    button.type = "button";
    button.dataset.action = entry.action.command;
    button.addEventListener("click", () =>
      run(entry.action, { id: entry.id, state: "trusted", trustedTitle: entry.title }),
    );
    row.append(button);
    return row;
  });
  section.querySelector(".trusted-list").replaceChildren(...rows);
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
    detail.push(id === "quarantine" ? renderQuarantineEntry(selected) : renderFinding(selected));
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
  // A banner replaces the sentence (spec section 8.6).
  renderBanner($("overview-banner"), overview.banner);
  $("overview-sentence").hidden = overview.sentence === null;
  $("overview-sentence").textContent = overview.sentence ?? "";
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
  renderGateLines(overview.gate);
}

// The Gate on the Overview (spec sections 7.6, 8.1 and 8.6): the Health
// lines the sentence does not say, and "Gate off in this project" for each
// project that switched the check off. Shown, never fought: no button.
function renderGateLines(gate) {
  const lines = gate.lines.map((line) => el("p", "muted", line));
  const projects = gate.projects.map((entry) => {
    const row = el("p", "gate-off");
    row.append(el("span", "project", entry.project), el("span", "muted", entry.line));
    return row;
  });
  $("overview-gate").replaceChildren(...lines, ...projects);
  $("overview-gate").hidden = lines.length + projects.length === 0;
}

// The record the Activity pane was asked to show, or null: the integrity
// flows open the pane at the break or at the restart record.
let activityFocus = null;
// True until the pane has scrolled to that record once.
let activityScroll = false;

// The technical columns the Developer Posture shows beside a line.
const ACTIVITY_COLUMNS = [
  ["action", "Action"],
  ["itemId", "Item id"],
  ["contentHash", "Content hash"],
  ["ruleId", "Rule id"],
  ["receiptId", "Receipt id"],
];

// The Activity pane (spec section 8.1): the daemon's lines, newest first,
// each with its moment and its unverified mark, and in the Developer Posture
// the record's technical columns beside it.
function renderActivity(activity, loaded) {
  const node = pane("activity");
  node.querySelector(".empty").hidden = !loaded || !activity.empty;
  const items = activity.lines.map((line) => {
    const item = el("li");
    if (line.sequence !== null) {
      item.dataset.sequence = String(line.sequence);
    }
    const head = el("p");
    head.append(el("span", "when", when(line.at)));
    head.append(el("span", "", line.line));
    if (line.mark !== null) {
      head.append(el("span", "chip", line.mark));
    }
    item.append(head);
    if (line.technical !== null) {
      const table = el("table", "technical");
      for (const [key, label] of ACTIVITY_COLUMNS) {
        if (line.technical[key] === null) {
          continue;
        }
        const tr = el("tr");
        tr.append(el("th", "", label));
        tr.append(el("td", "", line.technical[key]));
        table.append(tr);
      }
      item.append(table);
    }
    return item;
  });
  $("activity-lines").replaceChildren(...items);
  $("activity-note").hidden = activity.note === null;
  $("activity-note").textContent = activity.note ?? "";
  if (activityFocus !== null) {
    // The first record at or after the one asked for, which is the oldest
    // line still at or past it in a list that runs newest first.
    const at = items
      .filter((item) => item.dataset.sequence !== undefined && Number(item.dataset.sequence) >= activityFocus)
      .pop();
    if (at) {
      at.dataset.focus = "true";
      if (activityScroll) {
        at.scrollIntoView({ block: "center" });
        activityScroll = false;
      }
    }
  }
}

// Opens the Activity pane at the record with this sequence, or at the
// first one after it.
function showActivityAt(sequence) {
  select("activity");
  activityFocus = sequence;
  activityScroll = true;
  if (view) {
    render(view);
  }
}

// The Settings pane (spec section 8.10). Every choice is sent to the daemon
// through the app, and the pane shows the answer the app sends back with the
// next view, never what was clicked.
function settingsAnswer(text) {
  $("settings-answer").textContent = text;
}

async function changeSetting(change) {
  try {
    settingsAnswer(await invoke("change_settings", { change }));
  } catch (why) {
    settingsAnswer(String(why));
  }
  if (view) {
    render(view);
  }
}

function renderSettings(settings) {
  $("settings-note").hidden = settings.note === null;
  $("settings-note").textContent = settings.note ?? "";
  $("settings-off").hidden = settings.available;
  const disabled = !settings.available;

  const detail = $("settings-detail");
  detail.querySelector("h3").textContent = settings.detail.title;
  detail.querySelector(".choices").replaceChildren(
    ...settings.detail.choices.map((choice) => {
      const label = el("label", "choice");
      const input = el("input");
      input.type = "radio";
      input.name = "posture";
      input.checked = choice.selected;
      input.disabled = disabled;
      input.addEventListener("change", () => changeSetting({ posture: choice.posture }));
      label.append(input, el("span", "", choice.label));
      return label;
    }),
  );

  const background = $("settings-background");
  background.querySelector("h3").textContent = settings.background.title;
  background.querySelector(".disclosure").textContent = settings.background.disclosure;
  background.querySelector(".toggles").replaceChildren(
    ...settings.background.toggles.map((toggle) => {
      const label = el("label", "toggle");
      const input = el("input");
      input.type = "checkbox";
      input.checked = toggle.on;
      input.disabled = disabled;
      input.addEventListener("change", () => changeSetting({ [toggle.key]: input.checked }));
      label.append(input, el("span", "", toggle.label));
      return label;
    }),
  );

  const cli = $("settings-cli");
  cli.querySelector("h3").textContent = settings.cli.title;
  cli.querySelector(".line").textContent = settings.cli.line;
  cli.querySelector(".install").textContent = settings.cli.button;

  const advanced = $("settings-advanced");
  advanced.querySelector("h3").textContent = settings.advanced.title;
  advanced.querySelector(".dirs-line").textContent = settings.advanced.configDirsLine;
  const dirs = advanced.querySelector(".dirs");
  const typing = dirs.contains(document.activeElement);
  if (!typing) {
    dirs.replaceChildren(
      ...settings.advanced.configDirs.map((entry) => {
        const row = el("form", "dir");
        const input = el("input");
        input.type = "text";
        input.value = entry.dir ?? "";
        input.placeholder = entry.default;
        input.disabled = disabled;
        input.setAttribute("aria-label", entry.label);
        const save = el("button", "", "Save");
        save.type = "submit";
        save.disabled = disabled;
        row.addEventListener("submit", (event) => {
          event.preventDefault();
          changeSetting({ agent: entry.agent, dir: input.value });
        });
        row.append(el("span", "label", entry.label), input, save);
        return row;
      }),
    );
  }

  const everything = $("settings-everything");
  everything.querySelector("h4").textContent = settings.advanced.fullDiskAccess.title;
  everything
    .querySelector(".lines")
    .replaceChildren(...settings.advanced.fullDiskAccess.lines.map((line) => el("p", "muted", line)));
  everything.querySelector(".open").textContent = settings.advanced.fullDiskAccess.button;

  const rules = $("settings-rules");
  rules.querySelector("h4").textContent = settings.advanced.rules.title;
  rules.querySelector(".line").textContent = settings.advanced.rules.line;
  rules.querySelector(".path").textContent = settings.advanced.rules.path ?? "";
  rules.querySelector(".show").textContent = settings.advanced.rules.button;

  const notProtected = $("settings-not-protected");
  notProtected.querySelector("h3").textContent = settings.notProtected.title;
  notProtected.querySelector(".paragraph").textContent = settings.notProtected.paragraph;
  notProtected.querySelector(".link").textContent = settings.notProtected.link.label;

  const uninstall = $("settings-uninstall");
  uninstall.querySelector("h3").textContent = settings.uninstall.title;
  uninstall.querySelector(".line").textContent = settings.uninstall.line;
  uninstall.querySelector(".uninstall").textContent = settings.uninstall.button;
  uninstall.querySelector(".uninstall").disabled = disabled;
}

// Uninstall's dialog as the app worded it: answers the choice picked, or
// null when the user cancelled. Keep comes selected.
function askUninstall(offer) {
  const dialog = $("uninstall");
  $("uninstall-question").textContent = offer.question;
  $("uninstall-ok").textContent = offer.ok;
  $("uninstall-choices").replaceChildren(
    ...offer.choices.map((choice) => {
      const label = el("label", "choice");
      const input = el("input");
      input.type = "radio";
      input.name = "uninstall-choice";
      input.value = choice.choice;
      input.checked = choice.selected;
      label.append(input, el("span", "", choice.label), el("p", "muted", choice.line));
      return label;
    }),
  );
  return new Promise((resolve) => {
    dialog.addEventListener(
      "close",
      () => {
        const picked = dialog.querySelector("input[name=uninstall-choice]:checked");
        resolve(dialog.returnValue === "ok" && picked ? picked.value : null);
      },
      { once: true },
    );
    dialog.showModal();
  });
}

$("settings-cli")
  .querySelector(".install")
  .addEventListener("click", async () => {
    const answer = $("settings-cli").querySelector(".cli-answer");
    try {
      const lines = await invoke("install_cli");
      answer.replaceChildren(
        ...lines.map((line, index) =>
          el("p", index > 0 && line.startsWith("export ") ? "id" : "muted", line),
        ),
      );
    } catch (why) {
      answer.replaceChildren(el("p", "muted", String(why)));
    }
  });
$("settings-everything")
  .querySelector(".open")
  .addEventListener("click", () => invoke("open_full_disk_access").catch((why) => settingsAnswer(String(why))));
$("settings-rules")
  .querySelector(".show")
  .addEventListener("click", async () => {
    try {
      settingsAnswer(await invoke("show_rules_folder"));
    } catch (why) {
      settingsAnswer(String(why));
    }
  });
$("settings-uninstall")
  .querySelector(".uninstall")
  .addEventListener("click", async () => {
    const answer = $("settings-uninstall").querySelector(".uninstall-answer");
    try {
      const choice = await askUninstall(await invoke("uninstall_offer"));
      if (choice === null) {
        return;
      }
      const lines = await invoke("uninstall_agentsweep", { asked: { choice } });
      answer.replaceChildren(...lines.map((line) => el("p", "muted", line)));
    } catch (why) {
      answer.replaceChildren(el("p", "muted", String(why)));
    }
  });
$("settings-not-protected")
  .querySelector(".link")
  .addEventListener("click", () => invoke("open_not_protected").catch((why) => settingsAnswer(String(why))));

// The Gate switch in Background (spec section 8.10). The daemon writes and
// removes the entries; the switch shows where the daemon says it stands.
function renderGateSwitch(gate) {
  const label = el("label", "toggle");
  const input = el("input");
  input.type = "checkbox";
  input.checked = gate.on;
  input.disabled = !gate.available;
  input.addEventListener("change", async () => {
    input.disabled = true;
    try {
      settingsAnswer(await invoke("switch_gate", { on: input.checked }));
    } catch (why) {
      settingsAnswer(String(why));
    }
    if (view) {
      render(view);
    }
  });
  label.append(input, el("span", "", gate.label));
  const parts = [label, el("p", "muted", gate.subtitle)];
  for (const location of gate.locations ?? []) {
    parts.push(el("p", "id", location));
  }
  $("settings-gate").replaceChildren(...parts);
  $("settings-gate").hidden = false;
}

function render(list) {
  view = list;
  takePosture(list.posture);
  $("off").hidden = list.off === null;
  $("off").textContent = list.off === null ? "" : `Protection is off: ${list.off}.`;
  renderOverview(list.overview);
  renderSettings(list.settings);
  renderAiCheck(list.settings.aiCheck);
  renderGateSwitch(list.settings.gate);
  actionsWait = list.actionsWait;
  $("actions-wait").hidden = actionsWait === null;
  $("actions-wait").textContent = actionsWait === null ? "" : actionsWait;
  renderSidebar(list.sidebar);
  for (const id of FINDING_PANES) {
    renderFindingPane(id, list.panes[id], list.loaded);
  }
  renderTrusted(list.trusted ?? []);
  renderActivity(list.activity, list.loaded);
  renderAmbiguousList(list.ambiguous);
  disableActions();
}

// The Scan a folder dialog as the app sent it last, or null while it is
// closed.
let folderView = null;

// The dialog: open whenever the app sends a view, closed on null. While a
// Folder Scan runs another cannot be started from it. It never waits on the
// "checking now" rung: a Folder Scan may run beside another Scan.
function renderFolder(folder) {
  folderView = folder;
  const dialog = $("folder-dialog");
  if (!folder) {
    if (dialog.open) {
      dialog.close();
    }
    return;
  }
  if (!dialog.open) {
    dialog.showModal();
  }
  $("folder-choose").disabled = folder.state === "running";
  $("folder-root").textContent = folder.root ?? "";
  const command = isDeveloper() ? (folder.command ?? null) : null;
  $("folder-command").hidden = command === null;
  $("folder-command").textContent = command ?? "";
  const done = folder.state === "done";
  const section = $("folder");
  section.hidden = !done;
  section.dataset.safe = done ? String(folder.safe) : "";
  $("folder-line").textContent = done ? "" : (folder.line ?? "");
  if (!done) {
    $("folder-cards").replaceChildren();
    return;
  }
  $("folder-verdict").textContent = folder.verdict;
  $("folder-summary").textContent = folder.summary;
  $("folder-ambiguous").textContent = folder.ambiguous;
  $("folder-ambiguous").hidden = !isDeveloper();
  $("folder-recorded").textContent = folder.recorded;
  $("folder-pack").textContent = folder.rulePack;
  $("folder-cards").replaceChildren(...folder.findings.map(renderFolderCard));
}

onPostureChange(() => {
  if (folderView) {
    renderFolder(folderView);
  }
});

$("folder-choose").addEventListener("click", () =>
  invoke("choose_folder").catch((why) => {
    $("folder-line").textContent = String(why);
  }),
);
$("folder-close").addEventListener("click", () => $("folder-dialog").close());
// Closed by its button or by Escape: the app forgets it, so a window that
// loads later opens without it.
$("folder-dialog").addEventListener("close", () => {
  folderView = null;
  $("folder-drop").dataset.over = "false";
  invoke("close_folder").catch(() => {});
});

// True when a drag's position, in physical pixels of this webview, lies on
// the open dialog. A drop anywhere else is not a request.
function onFolderDialog(position) {
  const dialog = $("folder-dialog");
  if (!dialog.open || !position) {
    return false;
  }
  const scale = window.devicePixelRatio || 1;
  const x = position.x / scale;
  const y = position.y / scale;
  const box = dialog.getBoundingClientRect();
  return x >= box.left && x <= box.right && y >= box.top && y <= box.bottom;
}

// The drop zone: what the webview reports of a drag from Finder. The paths go
// to the app, which resolves them to one folder or refuses them; the page
// never decides what a path is.
const webview = window.__TAURI__.webview?.getCurrentWebview?.();
if (webview) {
  await webview.onDragDropEvent((event) => {
    const { type, position, paths } = event.payload;
    const zone = $("folder-drop");
    if (type === "enter" || type === "over") {
      zone.dataset.over = String(onFolderDialog(position));
      return;
    }
    zone.dataset.over = "false";
    if (type !== "drop" || !onFolderDialog(position) || folderView?.state === "running") {
      return;
    }
    invoke("scan_dropped", { paths: paths ?? [] }).catch((why) => {
      $("folder-line").textContent = String(why);
    });
  });
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
await listen("agentsweep://activity-at", (event) => showActivityAt(event.payload));
// A click on a notification brought the app to the front: the window turns
// to Needs your decision.
await listen("agentsweep://pane", (event) => select(event.payload));
renderFolder(await invoke("folder"));
render(await invoke("findings"));
