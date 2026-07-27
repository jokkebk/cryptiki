#!/usr/bin/env node
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { argon2id } from "../src/vendor/argon2.js";
import { b64, buildCapsule, detectLegacyFormat, hex } from "../src/migration-core.js";

const EXPECTED_COLUMNS = ["id", "keyhash", "passhash", "contenthash", "content", "accessed", "modified"];
const DEFAULT_ROWS = 251;
const SIX_MONTHS = 183 * 24 * 60 * 60 * 1000;
const nodeArgon2 = async (password, salt, options) => argon2id(password, salt, options);

function fail(message) { throw Error(`legacy dump rejected: ${message}`); }

function unescapeSql(value) {
  return value.replace(/\\([0abtnvfr'"\\%_])/g, (_, code) => ({ "0": "\0", a: "\x07", b: "\b", t: "\t", n: "\n", v: "\v", f: "\f", r: "\r", "'": "'", '"': '"', "\\": "\\", "%": "%", _: "_" }[code]));
}

function skipSpace(text, at) { while (at < text.length && /\s/.test(text[at])) at++; return at; }

function sqlValue(text, at) {
  at = skipSpace(text, at);
  if (text[at] === "'") {
    let out = ""; at++;
    while (at < text.length) {
      const char = text[at++];
      if (char === "'") return { value: unescapeSql(out), at };
      if (char === "\\" && at < text.length) out += `\\${text[at++]}`;
      else out += char;
    }
    fail("unterminated SQL string");
  }
  const start = at;
  while (at < text.length && !",)".includes(text[at])) at++;
  const value = text.slice(start, at).trim();
  if (!value || value.toUpperCase() === "NULL") fail("NULL or empty field");
  return { value, at };
}

function sqlTuple(text, at) {
  at = skipSpace(text, at);
  if (text[at] !== "(") fail("expected row tuple");
  at++;
  const values = [];
  for (;;) {
    const parsed = sqlValue(text, at); values.push(parsed.value); at = skipSpace(text, parsed.at);
    if (text[at] === ")") return { values, at: at + 1 };
    if (text[at] !== ",") fail("expected comma in row tuple");
    at++;
  }
}

function insertColumns(statement) {
  const match = /INSERT\s+INTO\s+`?pages`?\s*(?:\(([^)]*)\))?\s*VALUES/i.exec(statement);
  if (!match) return null;
  if (!match[1]) return EXPECTED_COLUMNS;
  const columns = match[1].split(",").map(value => value.trim().replaceAll("`", "").toLowerCase());
  if (columns.join("\0") !== EXPECTED_COLUMNS.join("\0")) fail("unexpected pages column order");
  return columns;
}

function nextInsert(text, from) {
  const re = /INSERT\s+INTO\s+`?pages`?\s*(?:\([^;]*?\))?\s*VALUES\s*/gi;
  re.lastIndex = from;
  const match = re.exec(text);
  return match ? { start: match.index, values: re.lastIndex } : null;
}

function endStatement(text, at) {
  let quote = false, escaped = false;
  for (; at < text.length; at++) {
    const char = text[at];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === "'") quote = false;
    } else if (char === "'") quote = true;
    else if (char === ";") return at;
  }
  fail("unterminated INSERT statement");
}

export function parseLegacyDump(text, expectedRows = DEFAULT_ROWS) {
  const schema = typeof text === "string" && text.match(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?pages`?[\s\S]*?;/i)?.[0];
  if (!schema || EXPECTED_COLUMNS.some(column => !new RegExp(`\\b${column}\\b`, "i").test(schema))) fail("pages schema is missing or unexpected");
  const rows = [];
  let cursor = 0, statementCount = 0;
  for (;;) {
    const insert = nextInsert(text, cursor);
    if (!insert) break;
    statementCount++;
    const end = endStatement(text, insert.values);
    const statement = text.slice(insert.start, end);
    insertColumns(statement);
    let at = insert.values;
    while (at < end) {
      const tuple = sqlTuple(text, at); at = skipSpace(text, tuple.at);
      if (tuple.values.length !== EXPECTED_COLUMNS.length) fail("pages row has the wrong number of fields");
      const [id, keyhash, passhash, contenthash, content, accessed, modified] = tuple.values;
      if (!/^\d+$/.test(id) || !/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(accessed) || !/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(modified)) fail("invalid row metadata");
      if (!/^[0-9a-fA-F]{64}$/.test(keyhash) || !/^[0-9a-fA-F]{64}$/.test(passhash) || !/^[0-9a-fA-F]{64}$/.test(contenthash)) fail("invalid row hash length");
      if (typeof content !== "string" || !content.length || content.length > 512 * 1024) fail("invalid row content");
      rows.push({ id: Number(id), keyhash: keyhash.toLowerCase(), passhash: passhash.toLowerCase(), contenthash: contenthash.toLowerCase(), content, accessed, modified });
      if (at < end && text[at] !== ",") fail("unexpected text in INSERT statement");
      if (text[at] === ",") at++;
    }
    cursor = end + 1;
  }
  if (statementCount === 0) fail("pages INSERT statement is missing");
  if (expectedRows !== null && rows.length !== expectedRows) fail(`expected ${expectedRows} unique rows, got ${rows.length}`);
  const ids = new Set(rows.map(row => row.id));
  if (ids.size !== rows.length) fail("duplicate row id");
  const keyhashes = new Set(rows.map(row => row.keyhash));
  if (keyhashes.size !== rows.length) fail("duplicate keyhash");
  return rows;
}

export function verifyCapsuleRecord(record) {
  const keys = Object.keys(record).sort().join("\0");
  if (keys !== ["blob", "created", "expires", "format", "lookup_id"].join("\0")) fail("import record contains unexpected fields");
  if (!/^[0-9a-f]{32}$/.test(record.lookup_id) || (record.format !== 1 && record.format !== 2) || !Number.isSafeInteger(record.created) || !Number.isSafeInteger(record.expires) || record.expires <= record.created) fail("invalid import record metadata");
  if (typeof record.blob !== "string" || !/^[A-Za-z0-9_-]+$/.test(record.blob) || record.blob.length % 4 === 1) fail("invalid import blob");
  const blob = Buffer.from(record.blob, "base64url");
  if (blob.length < 30 || blob[0] !== 1 || blob[1] !== record.format) fail("invalid import capsule");
  return blob;
}

export function verifyCapsuleFile(text, expectedRows = null) {
  const records = text.split(/\r?\n/).filter(Boolean).map(line => {
    let record; try { record = JSON.parse(line); } catch { fail("invalid import JSON"); }
    verifyCapsuleRecord(record); return record;
  });
  if (expectedRows !== null && records.length !== expectedRows) fail(`import file row count mismatch: ${records.length}`);
  const ids = new Set(records.map(record => record.lookup_id));
  if (ids.size !== records.length) fail("duplicate lookupId in import file");
  return records;
}

export async function convertRows(rows, created, expires, random) {
  const records = [], seen = new Set(), counts = { v1: 0, v2: 0 };
  for (const row of rows) {
    const record = await buildCapsule(row, created, expires, nodeArgon2, random);
    if (seen.has(record.lookup_id)) fail("duplicate lookupId");
    seen.add(record.lookup_id); counts[`v${record.format}`]++;
    records.push({ ...record, blob: b64(record.blob) });
  }
  return { records, counts };
}

function argument(name, args, required = true) {
  const index = args.indexOf(name);
  if (index < 0) { if (required) fail(`missing ${name}`); return null; }
  const value = args[index + 1]; if (!value || value.startsWith("--")) fail(`missing value for ${name}`); return value;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.length === 0) {
    console.log("usage: node tools/build-legacy-capsules.mjs --input dump.sql --output capsules.jsonl [--created ms] [--expires ms]");
    process.exit(args.length ? 0 : 2);
  }
  const input = argument("--input", args), output = argument("--output", args);
  const created = Number(argument("--created", args, false) || Date.now());
  const expires = Number(argument("--expires", args, false) || created + SIX_MONTHS);
  if (!Number.isSafeInteger(created) || !Number.isSafeInteger(expires) || expires <= created) fail("timestamps must be increasing safe integers");
  const rows = parseLegacyDump(readFileSync(input, "utf8"), DEFAULT_ROWS);
  const converted = await convertRows(rows, created, expires);
  const outputText = converted.records.map(record => JSON.stringify(record)).join("\n") + "\n";
  verifyCapsuleFile(outputText, rows.length);
  writeFileSync(output, outputText, { encoding: "utf8", mode: 0o600 });
  chmodSync(output, 0o600);
  const digest = createHash("sha256").update(outputText).digest("hex");
  console.log(`converted ${rows.length} rows (v1: ${converted.counts.v1}, v2: ${converted.counts.v2})`);
  console.log(`capsule output sha256: ${digest}`);
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
