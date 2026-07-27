import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
const headers = readFileSync(new URL("../public/_headers", import.meta.url), "utf8");
const hash = value => `sha256-${createHash("sha256").update(value).digest("base64")}`;
const style = html.match(/<style>([\s\S]*?)<\/style>/)?.[1];
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
if (!style || !script) throw Error("index.html must contain one inline style and script");
for (const expected of [hash(script), hash(style)]) if (!headers.includes(expected)) throw Error(`Missing CSP hash: ${expected}`);
if (headers.includes("REPLACE_")) throw Error("CSP placeholders remain");
if (/<script[^>]+src=|<link[^>]+href=/.test(html)) throw Error("index.html has an external dependency");
console.log(`CSP hashes verified: ${hash(script)} ${hash(style)}`);
