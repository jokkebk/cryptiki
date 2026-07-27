import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const headersUrl = new URL("../public/_headers", import.meta.url);

/** Routes served from each assembled page; every route pins the page's inline hashes. */
export const routes = {
  "index.html": ["/index.html"],
  "migrate.html": ["/legacy-migration", "/legacy-migration/", "/migrate"],
};

export const hash = value => `sha256-${createHash("sha256").update(value).digest("base64")}`;

/** Extracts the single inline style and script of an assembled page. */
export function inlineHashes(name, html) {
  const style = html.match(/<style>([\s\S]*?)<\/style>/)?.[1];
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  if (!style || !script) throw Error(`${name} must contain one inline style and script`);
  return { style: hash(style), script: hash(script) };
}

/** Rewrites the script-src/style-src hashes of a page's routes in public/_headers. */
export function syncCspHashes(name, html) {
  const { style, script } = inlineHashes(name, html);
  const paths = routes[name] ?? throwUnknown(name);
  const blocks = readFileSync(headersUrl, "utf8").split(/(?=^\/)/m);
  const seen = new Set();
  const updated = blocks.map(block => {
    const path = block.match(/^(\S+)/)?.[1];
    if (!paths.includes(path)) return block;
    seen.add(path);
    return block
      .replace(/script-src 'sha256-[^']*'/, `script-src '${script}'`)
      .replace(/style-src 'sha256-[^']*'/, `style-src '${style}'`);
  });
  const missing = paths.filter(path => !seen.has(path));
  if (missing.length) throw Error(`public/_headers has no block for ${missing.join(", ")}`);
  writeFileSync(headersUrl, updated.join(""));
  return { style, script };
}

const throwUnknown = name => { throw Error(`No CSP routes declared for ${name}`); };
