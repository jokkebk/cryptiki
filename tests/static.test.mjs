import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
const migration = readFileSync(new URL("../public/migrate.html", import.meta.url), "utf8");
const worker = readFileSync(new URL("../src/worker.js", import.meta.url), "utf8");

test("standalone deployed code stays local and within the budget", () => {
  assert.ok(html.includes('location.protocol === "file:"'));
  assert.ok(html.includes("https://cryptiki.com"));
  assert.doesNotMatch(html, /<(?:script|link)[^>]+(?:src|href)=["']https?:/i);
  assert.doesNotMatch(html, /\b(?:localStorage|sessionStorage|indexedDB)\s*\./);
  assert.doesNotMatch(html, /innerHTML/);
  /* The budget keeps the deployed code small enough to read end to end. Raised from 2100 on
     2026-07-28 for the audit fixes: bounded decoding, resumable rotation, the per-vault limiter,
     fail-closed edge identity, and the pristine-snapshot offline copy. Trim before raising again. */
  assert.ok(html.split("\n").length + worker.split("\n").length < 2150);
  assert.ok(Buffer.byteLength(html) + Buffer.byteLength(worker) < 112 * 1024);
});

test("Worker SQL is prepared-only and uses no legacy schema", () => {
  assert.doesNotMatch(worker, /`(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{/);
  assert.doesNotMatch(worker, /pages|keyhash|passhash|contenthash|AES-CTR|PBKDF2/);
  assert.match(worker, /If-None-Match/);
  assert.match(worker, /If-Match/);
});

test("temporary migration page is standalone and text-safe", () => {
  assert.doesNotMatch(migration, /<(?:script|link)[^>]+(?:src|href)=["']https?:/i);
  assert.doesNotMatch(migration, /\b(?:localStorage|sessionStorage|indexedDB)\s*\./);
  assert.doesNotMatch(migration, /innerHTML/);
  assert.match(migration, /api\/legacy\/recover/);
  assert.match(migration, /If-None-Match/);
  assert.match(migration, /Recovery window closes 2027-01-26/);
  assert.ok(Buffer.byteLength(migration) < 100 * 1024);
});

test("migration creation controls and feedback precede the recovered entry list", () => {
  const form = migration.indexOf('id="create-form"');
  const progress = migration.indexOf('id="create-progress"');
  const status = migration.indexOf('id="create-status"');
  const preview = migration.indexOf('id="preview"');
  assert.ok(form >= 0 && form < progress && progress < status && status < preview);
  assert.match(migration, /together they must total at least 24 characters/);
});

/* The regression this guards: the front page asked for a password twice with no explanation, and
   readers reasonably read the third box as part of unlocking. */
test("the unlock screen asks for one password, and Enter unlocks", () => {
  const screen = html.slice(html.indexOf('id="unlock-screen"'), html.indexOf('id="editor-screen"'));
  assert.equal((screen.match(/type="password"/g) || []).length, 2, "the unlock screen has more password fields than name + confirm");
  assert.match(screen, /id="confirm-field" hidden/, "the confirmation must stay hidden until create mode");
  assert.match(screen, /<button id="unlock" class="primary" type="submit"/, "Enter must submit the unlock form");
  assert.match(html, /\$\("unlock-form"\)\.addEventListener\("submit"/);
});
