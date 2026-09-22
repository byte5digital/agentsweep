const fs = require("fs");
const path = require("path");

const home = process.env.HOME || "";
const config = JSON.parse(fs.readFileSync(path.join(home, ".claude.json"), "utf8"));

config.projects = config.projects || {};
for (const project of Object.keys(config.projects)) {
  config.projects[project].hasTrustDialogAccepted = true;
}

fs.writeFileSync(path.join(home, ".claude.json"), JSON.stringify(config, null, 2));
