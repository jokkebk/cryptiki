#!/usr/bin/env node
import { chmodSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { verifyCapsuleFile } from "./build-legacy-capsules.mjs";

const CHUNK_HEX_LENGTH = 40000;
const MAX_FILE_LENGTH = 60000;

function fail(message) { throw Error(`capsule import rejected: ${message}`); }
function argument(name, args) {
  const index = args.indexOf(name); if (index < 0 || !args[index + 1] || args[index + 1].startsWith("--")) fail(`missing ${name}`); return args[index + 1];
}

export function capsuleStatements(text) {
  const records = verifyCapsuleFile(text);
  return records.flatMap(record => {
    const hex = Buffer.from(record.blob, "base64url").toString("hex");
    const statements = [`INSERT INTO legacy_capsules (lookup_id, format, blob, created, expires) VALUES ('${record.lookup_id}', ${record.format}, unhex(''), ${record.created}, ${record.expires});`];
    for (let at = 0; at < hex.length; at += CHUNK_HEX_LENGTH) {
      statements.push(`UPDATE legacy_capsules SET blob = unhex(hex(blob) || '${hex.slice(at, at + CHUNK_HEX_LENGTH)}') WHERE lookup_id = '${record.lookup_id}';`);
    }
    return statements;
  });
}

export function capsuleSql(text) {
  return `${capsuleStatements(text).join("\n")}\n`;
}

export function writeCapsuleChunks(text, outputDir) {
  if (readdirSync(outputDir, { withFileTypes: true }).length) fail("output directory must be empty");
  const statements = capsuleStatements(text);
  let fileIndex = 0, file = "";
  for (const statement of statements) {
    if (file && file.length + statement.length + 1 > MAX_FILE_LENGTH) {
      writeFileSync(`${outputDir}/chunk-${String(fileIndex++).padStart(4, "0")}.sql`, `${file}\n`, { encoding: "utf8", mode: 0o600 });
      file = "";
    }
    file += `${statement}\n`;
  }
  if (file) writeFileSync(`${outputDir}/chunk-${String(fileIndex++).padStart(4, "0")}.sql`, file, { encoding: "utf8", mode: 0o600 });
  return { files: fileIndex, statements: statements.length };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.length === 0) {
    console.log("usage: node tools/import-legacy-capsules.mjs --input capsules.jsonl (--output capsules.sql | --output-dir capsule-chunks)");
    process.exit(args.length ? 0 : 2);
  }
  const input = readFileSync(argument("--input", args), "utf8");
  const output = args.includes("--output") ? argument("--output", args) : null;
  const outputDir = args.includes("--output-dir") ? argument("--output-dir", args) : null;
  if ((output ? 1 : 0) + (outputDir ? 1 : 0) !== 1) fail("provide exactly one of --output or --output-dir");
  if (output) {
    const sql = capsuleSql(input);
    writeFileSync(output, sql, { encoding: "utf8", mode: 0o600 }); chmodSync(output, 0o600);
    console.log(`wrote ${capsuleStatements(input).length} capsule import statements`);
  } else {
    mkdirSync(outputDir, { recursive: true });
    const result = writeCapsuleChunks(input, outputDir);
    console.log(`wrote ${result.statements} capsule import statements in ${result.files} D1-safe files`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
