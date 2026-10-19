// The integrity and Protection banners (spec section 8.6), as the popover
// and the Overview render them. The app hands over the banner already
// worded for the Posture, with each button's command; this decides nothing.

const { invoke } = window.__TAURI__.core;

// Fills the banner elements under `root` (each found by its class) with
// `banner`, or hides `root` when there is none. A click calls the button's
// command; what it answers, or why it failed, is said on the banner's line.
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
  const buttons = banner.buttons.map((button, index) => {
    const node = document.createElement("button");
    node.type = "button";
    node.textContent = button.label;
    if (index === 0) {
      node.className = "primary";
    }
    node.addEventListener("click", async () => {
      try {
        const answer = await invoke(button.command);
        say(typeof answer === "string" ? answer : "");
      } catch (why) {
        say(String(why));
      }
    });
    return node;
  });
  part("banner-buttons").replaceChildren(...buttons);
}
