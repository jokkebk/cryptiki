import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const headers = readFileSync(new URL("../public/_headers", import.meta.url), "utf8");
const hash = value => `sha256-${createHash("sha256").update(value).digest("base64")}`;
for (const name of ["index.html", "migrate.html"]) {
  const html = readFileSync(new URL(`../public/${name}`, import.meta.url), "utf8");
  const style = html.match(/<style>([\s\S]*?)<\/style>/)?.[1];
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  if (!style || !script) throw Error(`${name} must contain one inline style and script`);
  for (const expected of [hash(script), hash(style)]) if (!headers.includes(expected)) throw Error(`Missing CSP hash for ${name}: ${expected}`);
  if (/<script[^>]+src=|<link[^>]+href=/.test(html)) throw Error(`${name} has an external dependency`);
  console.log(`${name} CSP hashes verified: ${hash(script)} ${hash(style)}`);
}
if (headers.includes("REPLACE_")) throw Error("CSP placeholders remain");
