import { readFileSync, writeFileSync } from "node:fs";
import { syncCspHashes } from "./csp.mjs";

const root = new URL("..", import.meta.url);
const read = name => readFileSync(new URL(name, root), "utf8");
const files = ["src/vendor/utils.js", "src/vendor/_blake.js", "src/vendor/_md.js", "src/vendor/_u64.js", "src/vendor/blake2.js", "src/vendor/argon2.js"];
const vendor = ["/* @noble/hashes 1.8.0 Argon2id vendor; MIT; source hash recorded in README. */", "const crypto = globalThis.crypto;", ...files.map(name => read(name))]
  .join("\n").replace(/^import .*;\n/gm, "").replace(/^export\s+\{[^}]+\};?\n/gm, "").replace(/^export\s+default .*;?\n/gm, "").replace(/export\s+(?=(const|function|class|async function)\b)/g, "");
const bundled = `${vendor}\nglobalThis.argon2idAsync = argon2idAsync;`;
const html = read("tools/index-template.html").replace("/* __VENDOR__ */", bundled).replace("/* __CLIENT__ */", read("src/client.js"));
writeFileSync(new URL("public/index.html", root), html);
syncCspHashes("index.html", html);
