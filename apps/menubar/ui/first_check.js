// The first check's result in the Findings window (spec section 8.3, screen
// 6): the Item count, the Baseline sentence, what was stopped and the
// result, as the app worded them. It shows once the first Scan after
// onboarding finished, whether the window was open then or opens later, and
// stays until it is closed, which tells the app. Everything is written with
// textContent, never as markup.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const dialog = $("first-check");

function show(view) {
  if (!view) {
    if (dialog.open) {
      dialog.close();
    }
    return;
  }
  $("first-check-title").textContent = view.title;
  $("first-check-items").textContent = view.items;
  $("first-check-baseline").textContent = view.baseline;
  $("first-check-stopped-line").textContent = view.stoppedLine;
  $("first-check-stopped").replaceChildren(
    ...view.stopped.map((title) => {
      const item = document.createElement("li");
      item.textContent = title;
      return item;
    }),
  );
  $("first-check-result").textContent = view.result;
  $("first-check-ok").textContent = view.button;
  if (!dialog.open) {
    dialog.showModal();
  }
}

// However it closes, the result was seen.
dialog.addEventListener("close", () => invoke("first_check_seen"));

await listen("agentsweep://first-check", (event) => show(event.payload));
show(await invoke("first_check"));
