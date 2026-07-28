import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const headersUrl = new URL("../public/_headers", import.meta.url);

/** Routes served from each assembled page; every route pins the page's inline hashes.
    Workers Assets serves a matching file without invoking the worker and matches header
    rules on the request path, so the path visitors actually use has to be listed too. */
export const routes = {
  "index.html": ["/", "/index.html"],
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

export function embedCsp(name, html) {
  const { style, script } = inlineHashes(name, html);
  const policy = `default-src 'none'; script-src '${script}'; style-src '${style}'; connect-src 'self' https://cryptiki.com; img-src data:; base-uri 'none'; form-action 'none'; require-trusted-types-for 'script'`;
  const embedded = html.replace('<meta http-equiv="Content-Security-Policy" content="__CSP_META__">', `<meta http-equiv="Content-Security-Policy" content="${policy}">`);
  if (embedded === html) throw Error(`${name} has no CSP meta placeholder`);
  return embedded;
}

/** Rewrites the script/style hashes in headers and embeds the same policy in the page. */
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
  return embedCsp(name, html);
}

const throwUnknown = name => { throw Error(`No CSP routes declared for ${name}`); };
