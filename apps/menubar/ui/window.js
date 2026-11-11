// The Findings window. It renders the frame the app hands over (the sidebar
// with its counts, one pane per entry, the Overview, the open Findings in the
// two Finding panes as a list beside the selected Finding) and the Scan a
// folder dialog, and invokes the app's commands; every decision about what
// is listed, counted and offered was made by the daemon and the app. Which
// pane and which Finding are selected is the window's own. Everything is
// written with textContent, never as markup. In the Simple Posture a
// Finding reads as the app worded it, in the three parts of layout B, and
// the Overview shows the Protection line and four count tiles (spec section
// 8.4); in the Developer Posture a Finding reads as `<Kind> · <name>` with
// its chips, the body lines and the technical table shown always, and the
// Threat Findings pane lists the Ambiguous Items beneath the Findings (spec
// sections 4.3 and 8.2).
//
// The action buttons are never disabled while a Scan runs (spec sections
// 6.4 and 6.6). A press is taken at once: from the click until the daemon
// answers, the Finding pressed shows the working line the app sent in place
// of its buttons ("Waiting for the check to finish…" while a Scan runs), and
// every press carries its own name, so the app carries it out once. Each
// part with buttons keeps its nodes while it shows the same (keep.js), so
// the next stream event's render cannot swallow a click.

import { renderBanner } from "./banner.js";
import { isDeveloper, onPostureChange, takePosture } from "./posture.js";
import { lookAtAiCheck, renderAiCheck } from "./ai_check.js";
import { keep } from "./keep.js";
import { nextPress } from "./press.js";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

// The Findings whose press waits for the daemon's answer, by id, each with
// the pane it was pressed in and its title: a Finding the stream moved out
// of its pane meanwhile stays in sight there with its working line.
const pending = new Map();

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
  if (result.falseAlarm) {
    node.append(renderFalseAlarmCard(result));
  }
  if (result.reported) {
    node.append(el("p", "muted", result.reported));
  }
  return node;
}

// The one-time card after a Restore or a Trust (spec section 8.8). Report
// it opens the dialog; No thanks dismisses it. Either way it is gone from
// this answer for good, and the next answer carries none unless it is
// another Restore or Trust.
function renderFalseAlarmCard(result) {
  const offer = result.falseAlarm;
  const node = el("div", "false-alarm");
  node.append(el("p", "", offer.question));
  const actions = el("div", "actions");
  const report = el("button", "", offer.report);
  report.type = "button";
  report.addEventListener("click", async () => {
    let said;
    try {
      said = await reportFalseAlarm(offer.target, offer.issue);
    } catch (why) {
      said = String(why);
    }
    if (said === null) {
      return;
    }
    result.falseAlarm = null;
    result.reported = said;
    if (view) {
      render(view);
    }
  });
  const dismiss = el("button", "", offer.dismiss);
  dismiss.type = "button";
  dismiss.addEventListener("click", () => {
    result.falseAlarm = null;
    if (view) {
      render(view);
    }
  });
  actions.append(report, dismiss);
  node.append(actions);
  return node;
}

// The false-alarm dialog: the issue the app prepared, written exactly as
// its address carries it (the app's `issue`, or asked for by the Finding).
// Open on GitHub asks the app to open that prepared issue in the browser;
// the window names only the Finding, never an address. Answers with the
// app's sentence, or null when the user cancelled.
async function reportFalseAlarm(target, issue) {
  const shown = issue ?? (await invoke("false_alarm_report", { target }));
  const dialog = $("false-alarm");
  $("false-alarm-heading").textContent = shown.heading;
  $("false-alarm-lead").textContent = shown.lead;
  $("false-alarm-title").textContent = shown.title;
  $("false-alarm-body").textContent = shown.body;
  $("false-alarm-open").textContent = shown.open;
  const confirmed = await new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok"), { once: true });
    dialog.showModal();
  });
  if (!confirmed) {
    return null;
  }
  return invoke("open_false_alarm_report", { target });
}

// Report false positive, where a Finding names a Rule, a Heuristic or a
// Verdict (spec section 8.8), or null.
function renderReport(card) {
  if (!card.report) {
    return null;
  }
  const report = el("button", "link", card.report);
  report.type = "button";
  report.addEventListener("click", async () => {
    try {
      const said = await reportFalseAlarm(card.id, null);
      if (said !== null) {
        showResult({ message: said, lines: [], details: [], choices: [], conflict: false }, card);
      }
    } catch (why) {
      showFailure(why, card);
    }
  });
  return report;
}

// A Finding's detail header in the Developer Posture: its title and Report
// false positive beside it.
function renderHeader(card, title) {
  const header = el("div", "card-header");
  header.append(el("p", "title", title));
  const report = renderReport(card);
  if (report) {
    header.append(report);
  }
  return header;
}

// One press of an action: its confirmation first where it has one, then the
// working line on that Finding at once, the request named for this press,
// and the answer beside the Finding.
async function run(action, card) {
  const id = card?.id ?? null;
  try {
    const asked = {
      trust: card?.trustConfirm,
      "restore-trust": card?.restoreConfirm,
      purge: card?.purgeConfirm,
    }[action.confirm];
    if (asked && !(await confirmWith(asked))) {
      return;
    }
    if (id !== null) {
      pending.set(id, { pane: paneOf(card), title: titleOf(card) });
      if (view) {
        render(view);
      }
    }
    const result = await invoke(action.command, {
      target: action.target,
      conflict: action.conflict,
      press: nextPress(),
    });
    pending.delete(id);
    showResult(result, card);
    if (result.conflict) {
      askConflict(result, card);
    }
  } catch (why) {
    pending.delete(id);
    showFailure(why, card);
  }
}

// What a pressed Finding shows in place of its buttons until the daemon
// answers: the line the app sent with the view.
function renderWorking() {
  const line = el("p", "working", view?.working ?? "");
  line.setAttribute("role", "status");
  return line;
}

// A Folder Scan's Finding in the Posture's wording: the Simple three parts
// with the technical details one click away, or the Developer heading with
// its chips and the technical table shown always. It recorded nothing, so
// it offers no action.
function renderFolderCard(card) {
  if (!isDeveloper()) {
    return renderSimpleCard(card, `folder ${card.id}`, () => renderFolder(folderView));
  }
  const node = el("article", "card");
  node.dataset.category = card.category;
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
  // A pressed Finding says it is working once, where its buttons in sight
  // were.
  if (behind.length > 0 && !pending.has(card.id)) {
    shown.append(renderActions(card, behind));
  }
  return shown;
}

// The buttons of one Finding: those the Posture shows in sight, or the ones
// given. While a press of one waits for the daemon's answer, the Finding
// shows the working line in their place.
function renderActions(card, actions = card.actions.filter((action) => !action.technical)) {
  const node = el("div", "actions");
  if (pending.has(card.id)) {
    node.append(renderWorking());
    return node;
  }
  for (const action of actions) {
    const button = el("button", "", action.label);
    button.type = "button";
    button.dataset.action = action.command;
    button.addEventListener("click", () => run(action, card));
    node.append(button);
  }
  return node;
}

// The folds the user opened on a Simple Finding (More, AI explanation and
// Show me how to fix this), by the Finding and the fold. A fold is a native
// disclosure; this remembers it, so a card built again opens as it was.
const foldsOpen = new Set();

// One fold, closed until the user opens it.
function renderFold(key, label, inner) {
  const fold = el("details", "fold");
  fold.open = foldsOpen.has(key);
  fold.addEventListener("toggle", () => {
    if (fold.open) {
      foldsOpen.add(key);
    } else {
      foldsOpen.delete(key);
    }
  });
  const body = el("div", "inner");
  body.append(...inner);
  fold.append(el("summary", "", label), body);
  return fold;
}

// One of the three parts: its small label and its sentence.
function renderPart(label, text) {
  const part = el("div", "part");
  part.append(el("span", "part-label", label), el("p", "", text));
  return part;
}

// What folds under More: the further signs as a list, the notes as muted
// lines.
function renderMore(lines) {
  const shown = [];
  let list = null;
  for (const line of lines) {
    if (line.part === "heuristic") {
      if (list === null) {
        list = el("ul", "heuristics");
        shown.push(list);
      }
      list.append(el("li", "", line.text));
      continue;
    }
    list = null;
    shown.push(el("p", "muted", line.text));
  }
  return shown;
}

// One Finding in the Simple Posture, in the three parts of layout B (spec
// section 8.4): the Severity chip beside the title that names the thing;
// What it is, Why it matters, and What to do with the buttons inside it;
// the how-to of an Exposure, the further signs and notes under More and the
// AI explanation each folded; Show technical details and Report false
// positive as links. No id, path, hash or Score is rendered here. A Folder
// Scan's Finding offers nothing, so it has no What to do; its technical
// details are kept under their own key.
function renderSimpleCard(card, details = card.id, again = () => render(view)) {
  const simple = card.simple;
  const parts = simple.parts;
  const node = el("article", "card");
  node.dataset.category = card.category;
  const head = el("div", "head");
  head.append(el("span", `chip ${simple.chip}`, simple.severity), el("p", "title", parts.name));
  node.append(head);
  const box = el("div", "parts");
  box.append(renderPart("What it is", parts.what), renderPart("Why it matters", parts.why));
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
  if (parts.todo) {
    const todo = renderPart("What to do", parts.todo);
    todo.classList.add("todo");
    if (actions.childElementCount > 0) {
      todo.append(actions);
    }
    box.append(todo);
  }
  node.append(box);
  if (card.howTo) {
    const howTo = card.howTo;
    node.append(
      renderFold(`${details} how-to`, howTo.label, [
        el("p", "", howTo.steps),
        el("p", "muted", `The file: ${howTo.file}`),
        renderOpenFile(card),
      ]),
    );
  }
  if (parts.more.length > 0) {
    node.append(renderFold(`${details} more`, "More", renderMore(parts.more)));
  }
  if (parts.ai) {
    // The engine's text, set as plain text, never markup.
    const ai = el("p", "ai");
    ai.append(el("span", "from", parts.ai.from), document.createTextNode(parts.ai.text));
    node.append(renderFold(`${details} ai`, "AI explanation", [ai]));
  }
  const links = el("div", "links");
  links.append(renderToggle(details, again));
  const report = renderReport(card);
  if (report) {
    links.append(report);
  }
  node.append(links);
  if (detailsOpen.has(details)) {
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
    // The AI block is the engine's text, set as plain text, never markup.
    node.append(el("p", muted ? "muted" : line.part === "ai" ? "ai" : "", line.text));
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
  node.append(renderHeader(card, developer.title));
  const chips = el("div", "chips");
  for (const chip of developer.chips) {
    const span = el("span", "chip", chip.text);
    span.dataset.fact = chip.fact;
    chips.append(span);
  }
  node.append(chips);
  renderLines(node, developer.lines ?? card.simple.lines);
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

// The Exposure Findings whose how-to is open in the Developer Posture, by id.
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
  section.append(renderOpenFile(card));
  node.append(section);
}

// Open the file under a how-to, which names only the Finding.
function renderOpenFile(card) {
  const file = el("button", "", card.howTo.open);
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
  return buttons;
}

// The Show technical details toggle of one Finding.
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

// One Ambiguous Item, in the Developer Posture only: one line with its
// title and its Score, and a click on it opens its Heuristic lines and its
// technical details beneath. It is not a Finding, so it offers no action.
function renderAmbiguous(item) {
  const key = `ambiguous:${item.id}`;
  const open = detailsOpen.has(key);
  const node = el("div", "ambiguous-item");
  node.setAttribute("role", "listitem");
  const row = el("button", "ambiguous-row");
  row.type = "button";
  row.setAttribute("aria-expanded", String(open));
  row.append(el("span", "title", item.title), el("span", "score", item.score));
  row.addEventListener("click", () => {
    if (detailsOpen.has(key)) {
      detailsOpen.delete(key);
    } else {
      detailsOpen.add(key);
    }
    render(view);
  });
  node.append(row);
  if (open) {
    const list = el("ul", "heuristics");
    for (const line of item.lines) {
      list.append(el("li", "", line));
    }
    node.append(list, renderTechnical(item));
  }
  return node;
}

// The Ambiguous Items below the Threat Findings, in a section closed until
// the user opens it, its count beside its name. The app sends them in the
// Developer Posture only; the Simple Posture never shows one (spec 8.4).
function renderAmbiguousList(items) {
  const section = pane("threats").querySelector(".ambiguous-items");
  const shown = isDeveloper() && Array.isArray(items) && items.length > 0;
  section.hidden = !shown;
  section.querySelector(".count").textContent = shown ? String(items.length) : "";
  const list = shown ? items : [];
  const open = list.filter((item) => detailsOpen.has(`ambiguous:${item.id}`)).map((item) => item.id);
  keep(section.querySelector(".list"), JSON.stringify([list, open]), () => list.map(renderAmbiguous));
}

// The "checked by <engine>" notes of Items a benign Verdict moved to Clear.
// The app sends them in the Developer Posture only (spec 8.2).
function renderCheckedList(items) {
  const section = pane("threats").querySelector(".checked-items");
  const shown = isDeveloper() && Array.isArray(items) && items.length > 0;
  section.hidden = !shown;
  section.querySelector(".list").replaceChildren(...(shown ? items.map((item) => el("li", "id", item.line)) : []));
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
  keep($("sidebar"), JSON.stringify([entries, selectedPane]), () => renderEntries(entries));
  for (const entry of entries) {
    pane(entry.pane).querySelector(".pane-title").textContent = entry.label;
    pane(entry.pane).hidden = entry.pane !== selectedPane;
  }
}

function renderEntries(entries) {
  return entries.map((entry) => {
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
}

function renderRow(id, card) {
  const row = el("button", "row");
  row.type = "button";
  row.setAttribute("role", "listitem");
  row.dataset.category = card.category;
  // The whole title, wrapped, and in the Simple Posture the project or
  // Agent under it.
  const text = el("span", "text");
  if (isDeveloper()) {
    text.append(el("span", "title", card.developer.title));
    row.append(text, el("span", "chip", card.severity));
  } else {
    text.append(el("span", "title", card.simple.title));
    if (card.simple.place) {
      text.append(el("span", "place", card.simple.place));
    }
    row.append(text, el("span", `chip ${card.simple.chip}`, card.simple.severity));
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
// chips (in the Simple Posture its title), who stopped it and when, the
// withdrawn Rule line, the fixed version line and, in the Developer Posture
// only, the Receipt id.
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
  (node.querySelector(".chips") ?? node.querySelector(".head")).after(lines);
  return node;
}

// The Trusted section at the foot of the Quarantine pane, each with Stop
// trusting this in both Postures. Its answer shows in the pane's detail.
function renderTrusted(entries) {
  const section = pane("quarantine").querySelector(".trusted");
  section.hidden = entries.length === 0;
  const waiting = entries.filter((entry) => pending.has(entry.id)).map((entry) => entry.id);
  const key = JSON.stringify([entries, waiting, waiting.length > 0 ? view?.working : null]);
  keep(section.querySelector(".trusted-list"), key, () =>
    entries.map((entry) => {
      const row = el("div", "trusted-entry");
      row.setAttribute("role", "listitem");
      row.append(el("span", "title", entry.title));
      if (pending.has(entry.id)) {
        row.append(renderWorking());
        return row;
      }
      const button = el("button", "", entry.action.label);
      button.type = "button";
      button.dataset.action = entry.action.command;
      button.addEventListener("click", () =>
        run(entry.action, { id: entry.id, state: "trusted", trustedTitle: entry.title }),
      );
      row.append(button);
      return row;
    }),
  );
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
  // An answer stays beside its Finding, even once the Finding left the pane,
  // and so does a press that waits for its answer.
  const kept = answer !== null && answer.pane === id && answer.id === selectedFinding[id];
  const pressed = pending.get(selectedFinding[id]);
  const held = !kept && pressed !== undefined && pressed.pane === id;
  if (!kept && !held && !cards.some((card) => card.id === selectedFinding[id])) {
    selectedFinding[id] = cards.length > 0 ? cards[0].id : null;
  }
  node.querySelector(".empty").hidden = !loaded || cards.length > 0 || kept || held;
  node.querySelector(".split").hidden = cards.length === 0 && !kept && !held;
  const developer = isDeveloper();
  keep(node.querySelector(".list"), JSON.stringify([cards, selectedFinding[id], developer]), () =>
    cards.map((card) => renderRow(id, card)),
  );
  const selected = cards.find((card) => card.id === selectedFinding[id]);
  // Everything the detail is built from: an unchanged Finding keeps its
  // card, its buttons included, through every render.
  const waiting = (selected !== undefined && pending.has(selected.id)) || held;
  const key = JSON.stringify({
    selected: selected ?? null,
    answer: kept ? answer : null,
    held: held ? pressed.title : null,
    waiting,
    working: waiting ? (view?.working ?? null) : null,
    details: selected !== undefined && detailsOpen.has(selected.id),
    howTo: selected !== undefined && howToOpen.has(selected.id),
    developer,
  });
  keep(node.querySelector(".detail"), key, () => {
    const detail = [];
    if (selected) {
      detail.push(id === "quarantine" ? renderQuarantineEntry(selected) : renderFinding(selected));
    } else if (kept) {
      detail.push(el("p", "title", answer.title));
    } else if (held) {
      detail.push(el("p", "title", pressed.title), renderWorking());
    }
    if (kept) {
      detail.push(renderAnswer(answer.result));
    }
    return detail;
  });
}

// A moment in local time, as the popover writes it.
function when(text) {
  const moment = new Date(text);
  if (Number.isNaN(moment.getTime())) {
    return text;
  }
  return moment.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

// A moment as the Simple Overview's watching line says it: "today, 09:12",
// or the date and the time on another day.
function lastCheck(text) {
  const moment = new Date(text);
  if (Number.isNaN(moment.getTime())) {
    return text;
  }
  const time = moment.toLocaleTimeString(undefined, { timeStyle: "short" });
  if (moment.toDateString() === new Date().toDateString()) {
    return `today, ${time}`;
  }
  return `${moment.toLocaleDateString(undefined, { dateStyle: "medium" })}, ${time}`;
}

// What "Scan now" answered, shown until the stream says more.
let scanAnswer = "";

// The project tiles the user opened on the Simple Overview: each shows the
// projects it counts beneath the tiles.
const tilesOpen = new Set();

// The Overview pane (spec section 8.1). With Protection off it shows the
// sentence alone and offers neither Scan action (spec section 6.2). The
// Simple Posture shows layout B (spec section 8.4): the Protection line,
// the four tiles and one line naming the Agents watched with the last
// check; the Developer Posture the sentence, one line per Agent, the last
// check and the date of the rules.
function renderOverview(overview) {
  // A banner replaces the sentence and the Protection line (spec section
  // 8.6).
  renderBanner($("overview-banner"), overview.banner);
  $("overview-protection").hidden = (overview.protection ?? null) === null;
  $("overview-protection").textContent = overview.protection ?? "";
  $("overview-sentence").hidden = overview.sentence === null;
  $("overview-sentence").textContent = overview.sentence ?? "";
  $("overview-body").hidden = overview.off;
  $("overview-scan").hidden = !overview.actions;
  const tiled = renderTiles(overview);
  const agents = overview.agents.map((agent) => {
    const item = el("li", "", agent.line);
    item.dataset.agent = agent.agent;
    item.dataset.installed = String(agent.installed);
    return item;
  });
  $("overview-agents").replaceChildren(...agents);
  if (tiled) {
    const checked = overview.lastCheck
      ? `Last check ${lastCheck(overview.lastCheck)}.`
      : "Nothing checked yet.";
    $("overview-last-check").textContent = [overview.watching, checked]
      .filter(Boolean)
      .join(" ");
  } else {
    $("overview-last-check").textContent = overview.lastCheck
      ? `Last check: ${when(overview.lastCheck)}`
      : "Nothing checked yet.";
  }
  $("overview-rules").textContent = overview.rulesUpdated ?? "";
  $("overview-rules").hidden = overview.rulesUpdated === null;
  if (overview.scan.running) {
    scanAnswer = "";
  }
  $("scan-line").textContent = overview.scan.running ? overview.scan.progress : scanAnswer;
  $("overview-summary").textContent = overview.summary ?? "";
  $("overview-summary").hidden = overview.summary === null;
  // "AI check: 3 of 12" in the Developer Posture; the cap line in both.
  $("overview-ai-check").textContent = overview.aiCheck ?? "";
  $("overview-ai-check").hidden = (overview.aiCheck ?? null) === null;
  $("overview-cap").textContent = overview.cap ?? "";
  $("overview-cap").hidden = (overview.cap ?? null) === null;
  renderGateLines(overview.gate, tiled);
  renderPermission(overview.permission, tiled);
}

// The four count tiles of the Simple Overview, from the frame: the count,
// the label and the tone each. A Finding tile opens its pane; a project tile
// opens the projects it counts and has nothing to open at zero. Check now
// stands on the tile of the projects not checked. The tiles are the page's
// own nodes, filled in place, so a render never swallows a click on them.
// Answers true when the tiles are shown.
function renderTiles(overview) {
  const tiles = overview.tiles ?? [];
  $("overview-tiles").hidden = tiles.length === 0;
  for (const tile of tiles) {
    const node = $("overview-tiles").querySelector(`[data-tile="${tile.tile}"]`);
    node.dataset.tone = tile.tone ?? "";
    node.querySelector(".n").textContent = String(tile.count);
    node.querySelector(".label").textContent = tile.label;
    if (tile.tile === "permission" || tile.tile === "gate") {
      if (tile.count === 0) {
        tilesOpen.delete(tile.tile);
      }
      const open = node.querySelector(".open");
      open.disabled = tile.count === 0;
      open.setAttribute("aria-expanded", String(tilesOpen.has(tile.tile)));
    }
  }
  const permission = overview.permission ?? null;
  $("tile-check-now").hidden = tiles.length === 0 || permission === null;
  if (permission !== null) {
    $("tile-check-now").textContent = permission.button;
    $("tile-check-now").disabled = !permission.enabled;
  }
  return tiles.length > 0;
}

// The Gate on the Overview (spec sections 7.6, 8.1 and 8.6): the Health
// lines the sentence does not say, and "Gate off in this project" for each
// project that switched the check off; under the tiles, those projects show
// once their tile is opened. Shown, never fought: no button.
function renderGateLines(gate, tiled) {
  const lines = gate.lines.map((line) => el("p", "muted", line));
  const listed = !tiled || tilesOpen.has("gate") ? gate.projects : [];
  const projects = listed.map((entry) => {
    const row = el("p", "gate-off");
    row.append(el("span", "project", entry.project), el("span", "muted", entry.line));
    return row;
  });
  $("overview-gate").replaceChildren(...lines, ...projects);
  $("overview-gate").hidden = lines.length + projects.length === 0;
}

// "N projects not checked" with Check now, for projects that Need
// Permission (spec section 8.6). The button stays disabled until the daemon
// answers; after an answer the link to System Settings shows while projects
// still Need Permission. Under the tiles, the tile says the line and holds
// Check now, and the projects show once the tile is opened; the link and an
// answer show either way.
function renderPermission(permission, tiled) {
  const opened = tiled && tilesOpen.has("permission");
  $("overview-permission").hidden =
    permission === null ||
    (tiled && !opened && permission.privacy === null && $("permission-answer").hidden);
  if (permission === null) {
    return;
  }
  $("permission-line").hidden = tiled;
  $("check-now").hidden = tiled;
  $("permission-projects").hidden = tiled && !opened;
  $("permission-line").textContent = permission.line;
  $("permission-projects").replaceChildren(
    ...permission.projects.map((project) => el("li", "", project)),
  );
  $("check-now").textContent = permission.button;
  $("check-now").disabled = !permission.enabled;
  $("permission-privacy").hidden = permission.privacy === null;
  if (permission.privacy !== null) {
    $("privacy-sentence").textContent = permission.privacy.sentence;
    $("open-privacy").textContent = permission.privacy.button;
  }
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

// One Activity line: its moment, its sentence and its unverified mark, and
// in the Developer Posture the record's technical columns beside it.
function renderActivityLine(line) {
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
}

// The Activity pane (spec section 8.1): the daemon's lines, newest first,
// the newest 500 at first and 500 more with each Show older. The list keeps
// its nodes while its lines stay the same (keep.js), so a stream event does
// not build it again.
function renderActivity(activity, loaded) {
  const node = pane("activity");
  node.querySelector(".empty").hidden = !loaded || !activity.empty;
  const list = $("activity-lines");
  keep(list, JSON.stringify(activity.lines), () => activity.lines.map(renderActivityLine));
  $("activity-older").hidden = !activity.older;
  $("activity-note").hidden = activity.note === null;
  $("activity-note").textContent = activity.note ?? "";
  $("activity-ai-check").textContent = activity.aiCheck ?? "";
  $("activity-ai-check").hidden = (activity.aiCheck ?? null) === null;
  for (const marked of list.querySelectorAll("[data-focus]")) {
    delete marked.dataset.focus;
  }
  if (activityFocus !== null) {
    // The first record at or after the one asked for, which is the oldest
    // line still at or past it in a list that runs newest first.
    const at = [...list.children]
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

// Show older: the app answers with the view holding the next 500 lines.
$("activity-older").addEventListener("click", async () => {
  render(await invoke("show_older"));
});

// The Settings pane (spec section 8.10). Every choice is sent to the daemon
// through the app, and the pane shows the answer the app sends back with the
// next view, never what was clicked.
function settingsAnswer(text) {
  $("settings-answer").textContent = text;
}

// How many settings changes the daemon answered. The radios, toggles and
// the Gate switch keep their nodes while it stays the same (keep.js), so a
// render cannot swallow a click on one; an answer builds them again from the
// view, so a change the daemon refused does not stay ticked.
let settingsAnswered = 0;

async function changeSetting(change) {
  try {
    settingsAnswer(await invoke("change_settings", { change }));
  } catch (why) {
    settingsAnswer(String(why));
  }
  settingsAnswered += 1;
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
  const choices = JSON.stringify([settings.detail.choices, disabled, settingsAnswered]);
  keep(detail.querySelector(".choices"), choices, () =>
    settings.detail.choices.map((choice) => {
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
  const toggles = JSON.stringify([settings.background.toggles, disabled, settingsAnswered]);
  keep(background.querySelector(".toggles"), toggles, () =>
    settings.background.toggles.map((toggle) => {
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
// removes the entries; the switch shows where the daemon says it stands. It
// keeps its node while that stays the same, and waits greyed out, as the
// user left it, until the daemon answered.
function renderGateSwitch(gate) {
  keep($("settings-gate"), JSON.stringify([gate, settingsAnswered]), () => {
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
      settingsAnswered += 1;
      if (view) {
        render(view);
      }
    });
    label.append(input, el("span", "", gate.label));
    const parts = [label, el("p", "muted", gate.subtitle)];
    for (const location of gate.locations ?? []) {
      parts.push(el("p", "id", location));
    }
    return parts;
  });
  $("settings-gate").hidden = false;
}

// The Settings tab in sight, by the id of its panel (spec section 8.10). A
// tab whose settings are all hidden, the AI check before the daemon answered,
// is hidden too, and General shows in its place.
let settingsTab = "settings-panel-general";

function renderSettingsTabs() {
  const tabs = [...$("settings-tabs").querySelectorAll("[role=tab]")];
  for (const tab of tabs) {
    const settings = [...$(tab.getAttribute("aria-controls")).querySelectorAll(".setting")];
    tab.hidden = settings.every((setting) => setting.hidden);
  }
  if (!tabs.some((tab) => !tab.hidden && tab.getAttribute("aria-controls") === settingsTab)) {
    settingsTab = "settings-panel-general";
  }
  for (const tab of tabs) {
    const panel = tab.getAttribute("aria-controls");
    tab.setAttribute("aria-selected", String(panel === settingsTab));
    $(panel).hidden = panel !== settingsTab;
  }
}

for (const tab of $("settings-tabs").querySelectorAll("[role=tab]")) {
  tab.addEventListener("click", () => {
    settingsTab = tab.getAttribute("aria-controls");
    renderSettingsTabs();
    pane("settings").scrollTop = 0;
  });
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
  renderSettingsTabs();
  renderSidebar(list.sidebar);
  for (const id of FINDING_PANES) {
    renderFindingPane(id, list.panes[id], list.loaded);
  }
  renderTrusted(list.trusted ?? []);
  renderActivity(list.activity, list.loaded);
  renderAmbiguousList(list.ambiguous);
  renderCheckedList(list.checked);
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
    scanAnswer = await invoke("scan_now", { press: nextPress() });
    $("scan-line").textContent = scanAnswer;
  } catch (why) {
    $("scan-line").textContent = String(why);
  }
});
// Check now sends check-now once per press; the button says "Checking…"
// and waits until the daemon answers, and the stream shows the projects once
// they are checked. The Simple Overview's tile carries its own button for
// the same request.
async function checkNow(button) {
  button.disabled = true;
  $("permission-answer").hidden = true;
  try {
    await invoke("check_now", { press: nextPress() });
  } catch (why) {
    $("permission-answer").textContent = String(why);
    $("permission-answer").hidden = false;
    $("overview-permission").hidden = false;
  }
}
$("check-now").addEventListener("click", () => checkNow($("check-now")));
$("tile-check-now").addEventListener("click", () => checkNow($("tile-check-now")));
// A Finding tile opens its pane; a project tile opens or closes the
// projects it counts.
for (const tile of $("overview-tiles").querySelectorAll(".tile")) {
  tile.querySelector(".open").addEventListener("click", () => {
    const name = tile.dataset.tile;
    if (name === "threats" || name === "exposures") {
      select(name);
      return;
    }
    if (tilesOpen.has(name)) {
      tilesOpen.delete(name);
    } else {
      tilesOpen.add(name);
    }
    if (view) {
      render(view);
    }
  });
}
$("open-privacy").addEventListener("click", () =>
  invoke("open_privacy").catch((why) => {
    $("permission-answer").textContent = String(why);
    $("permission-answer").hidden = false;
  }),
);
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
