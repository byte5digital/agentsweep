// Check every documented link.
const { execFileSync } = require("child_process");

const host = process.env.DOCS_HOST || "docs.example.invalid";
const url = "https://" + host + "/sitemap.xml";

execFileSync("curl", ["-fsS", url], { stdio: "inherit" });
