import { readFileSync, writeFileSync } from "node:fs";
import { syncCspHashes } from "./csp.mjs";

const root = new URL("..", import.meta.url);
const read = name => readFileSync(new URL(name, root), "utf8");
const vendorFiles = ["src/vendor/utils.js", "src/vendor/_blake.js", "src/vendor/_md.js", "src/vendor/_u64.js", "src/vendor/blake2.js", "src/vendor/argon2.js"];
const vendor = ["/* @noble/hashes 1.8.0 Argon2id vendor; MIT; source hash recorded in README. */", "const crypto = globalThis.crypto;", ...vendorFiles.map(read)]
  .join("\n").replace(/^import .*;\n/gm, "").replace(/^export\s+\{[^}]+\};?\n/gm, "").replace(/^export\s+default .*;?\n/gm, "").replace(/export\s+(?=(const|function|class|async function)\b)/g, "");
const argon2 = `${vendor}\nglobalThis.argon2idAsync = argon2idAsync;`;
const core = read("src/migration-core.js").replace(/^export\s+\{[^}]+\};?\n/gm, "").replace(/export\s+(?=(const|function|class|async function)\b)/g, "");
const html = read("tools/migration-template.html").replace("/* __ARGON2__ */", argon2).replace("/* __CORE__ */", core).replace("/* __MIGRATION_APP__ */", read("src/migration.js"));
writeFileSync(new URL("public/migrate.html", root), html);
syncCspHashes("migrate.html", html);
