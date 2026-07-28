import { readFileSync } from "node:fs";
import { inlineHashes, routes } from "./csp.mjs";

const headers = readFileSync(new URL("../public/_headers", import.meta.url), "utf8");
const blocks = headers.split(/(?=^\/)/m);
for (const [name, paths] of Object.entries(routes)) {
  const html = readFileSync(new URL(`../public/${name}`, import.meta.url), "utf8");
  const { style, script } = inlineHashes(name, html);
  assertMetaPolicy(name, html, style, script);
  for (const path of paths) {
    const block = blocks.find(b => b.match(/^(\S+)/)?.[1] === path);
    if (!block) throw Error(`public/_headers has no block for ${path}`);
    for (const expected of [script, style]) {
      if (!block.includes(expected)) throw Error(`Stale CSP hash for ${path} (${name}): expected ${expected}. Run npm run assemble${name === "migrate.html" ? ":migrate" : ""}`);
    }
  }
  if (/<script[^>]+src=|<link[^>]+href=/.test(html)) throw Error(`${name} has an external dependency`);
  console.log(`${name} CSP hashes verified on ${paths.join(", ")}: ${script} ${style}`);
}
if (headers.includes("REPLACE_")) throw Error("CSP placeholders remain");

function assertMetaPolicy(name, html, style, script) {
  const meta = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)?.[1];
  if (!meta || !meta.includes("default-src 'none'") || !meta.includes(script) || !meta.includes(style) || !meta.includes("connect-src 'self' https://cryptiki.com") || !meta.includes("require-trusted-types-for 'script'")) throw Error(`${name} has no complete embedded CSP policy`);
}
