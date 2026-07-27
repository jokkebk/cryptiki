#!/usr/bin/env node
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { verifyCapsuleFile } from "./build-legacy-capsules.mjs";

function fail(message) { throw Error(`capsule import rejected: ${message}`); }
function argument(name, args) {
  const index = args.indexOf(name); if (index < 0 || !args[index + 1] || args[index + 1].startsWith("--")) fail(`missing ${name}`); return args[index + 1];
}

export function capsuleSql(text) {
  const records = verifyCapsuleFile(text);
  const statements = records.map(record => {
    const blob = Buffer.from(record.blob, "base64url").toString("hex");
    return `INSERT INTO legacy_capsules (lookup_id, format, blob, created, expires) VALUES ('${record.lookup_id}', ${record.format}, X'${blob}', ${record.created}, ${record.expires});`;
  });
  return `BEGIN TRANSACTION;\n${statements.join("\n")}\nCOMMIT;\n`;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.length === 0) {
    console.log("usage: node tools/import-legacy-capsules.mjs --input capsules.jsonl --output capsules.sql");
    process.exit(args.length ? 0 : 2);
  }
  const output = argument("--output", args); const sql = capsuleSql(readFileSync(argument("--input", args), "utf8"));
  writeFileSync(output, sql, { encoding: "utf8", mode: 0o600 }); chmodSync(output, 0o600);
  console.log(`wrote ${sql.split("\n").filter(line => line.startsWith("INSERT")).length} capsule import statements`);
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
