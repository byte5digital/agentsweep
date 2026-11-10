// The integrity and Protection banners (spec section 8.6), as the popover
// and the Overview render them. The app hands over the banner already
// worded for the Posture, with each button's command; this decides nothing.

import { keep } from "./keep.js";
import { nextPress } from "./press.js";

const { invoke } = window.__TAURI__.core;

// Fills the banner elements under `root` (each found by its class) with
// `banner`, or hides `root` when there is none. A click names the press and
// calls the button's command; from the click until the answer the button
// waits and the banner's line says it is working ("Starting AgentSweep…" for
// Start it), then says what it answered, or why it failed. The buttons keep
// their nodes while the banner shows the same ones, so a render cannot
// swallow a click.
export function renderBanner(root, banner) {
  root.hidden = banner === null;
  if (banner === null) {
    return;
  }
  const part = (name) => root.querySelector(`.${name}`);
  root.dataset.tone = banner.tone;
  part("banner-title").textContent = banner.title;
  part("banner-body").textContent = banner.body;
  part("banner-developer").textContent = banner.developer ?? "";
  part("banner-developer").hidden = banner.developer === null;
  const line = part("banner-line");
  const say = (text) => {
    line.textContent = text;
    line.hidden = text === "";
  };
  keep(part("banner-buttons"), JSON.stringify(banner.buttons), () =>
    banner.buttons.map((button, index) => {
      const node = document.createElement("button");
      node.type = "button";
      node.textContent = button.label;
      if (index === 0) {
        node.className = "primary";
      }
      node.addEventListener("click", async () => {
        node.disabled = true;
        say(button.working);
        try {
          const answer = await invoke(button.command, { press: nextPress() });
          say(typeof answer === "string" ? answer : "");
        } catch (why) {
          say(String(why));
        }
        node.disabled = false;
      });
      return node;
    }),
  );
}
