import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createHash, pbkdf2Sync } from "node:crypto";
import { argon2id } from "../src/vendor/argon2.js";
import { b64, buildCapsule, decryptCapsule, decryptV3, deriveCapsuleMaterial, deriveLegacy, deriveV3, detectLegacyFormat, encryptV3, hex, parseLegacyEntries, verifyPlaintext, v1Decrypt, v2Decrypt } from "../src/migration-core.js";
import { convertRows, parseLegacyDump, verifyCapsuleFile } from "../tools/build-legacy-capsules.mjs";
import { capsuleSql } from "../tools/import-legacy-capsules.mjs";

const enc = new TextEncoder();
const argon = async (password, salt, options) => argon2id(password, salt, options);
const shaHex = value => createHash("sha256").update(value).digest("hex");

function v1Encrypt(plaintext, password) {
  const padded = Buffer.alloc(32); Buffer.from(password, "utf8").copy(padded, 0, 0, 32);
  const ecb = createCipheriv("aes-256-ecb", padded, null); ecb.setAutoPadding(false);
  const key16 = Buffer.concat([ecb.update(padded.subarray(0, 16)), ecb.final()]);
  const counter = Buffer.alloc(16); Buffer.from("12345678").copy(counter);
  const ctr = createCipheriv("aes-256-ctr", Buffer.concat([key16, key16]), counter);
  return Buffer.concat([counter.subarray(0, 8), ctr.update(Buffer.from(plaintext, "utf8")), ctr.final()]).toString("base64");
}

function v2Encrypt(plaintext, name, password) {
  const keyhash = pbkdf2Sync(Buffer.from(name), Buffer.from("Cryptiki 2.0"), 133700, 32, "sha256");
  const passhash = pbkdf2Sync(Buffer.from(password), keyhash, 133700, 32, "sha256");
  const iv = Buffer.from("0123456789abcdef"); const ctr = createCipheriv("aes-256-ctr", passhash, iv);
  return { keyhash: keyhash.toString("hex"), passhash: passhash.toString("hex"), content: JSON.stringify({ iv: iv.toString("hex"), deriv: "PBKDF2", iter: 133700, hash: "SHA256", salt: "Cryptiki 2.0", crypto: "AES256CTR", encrypted: Buffer.concat([ctr.update(Buffer.from(plaintext)), ctr.final()]).toString("base64") }) };
}

const v1Name = "v1 synthetic";
const v1Password = "pāssword-1";
const v1Plaintext = "mail: alice / correct horse\nA note with <unsafe> text";
const v1Content = v1Encrypt(v1Plaintext, v1Password);
const v1Row = { id: 1, keyhash: shaHex(Buffer.from(v1Name)), passhash: shaHex(Buffer.from(v1Password)), contenthash: shaHex(Buffer.from(v1Plaintext)), content: v1Content, accessed: "2026-07-27 00:00:00", modified: "2026-07-27 00:00:00" };

test("v1 legacy AES-CTR vector decrypts and parses safely", async () => {
  assert.equal(detectLegacyFormat(v1Content), 1);
  assert.equal(await v1Decrypt(v1Content, v1Password), v1Plaintext);
  assert.equal(await verifyPlaintext(v1Plaintext, v1Row.contenthash), true);
  const entries = parseLegacyEntries(v1Plaintext, 1);
  assert.equal(entries.length, 1); assert.equal(entries[0].service, "mail"); assert.match(entries[0].note, /unsafe/);
  let wrong = ""; try { wrong = await v1Decrypt(v1Content, "wrong password"); } catch { /* wrong v1 passwords may decode as invalid UTF-8 */ }
  assert.notEqual(wrong, v1Plaintext);
});

test("v2 PBKDF2 and AES-CTR vector decrypts and parses safely", async () => {
  const plaintext = JSON.stringify([{ service: "mail", username: "bob", password: "secret", text: "note" }]);
  const v2 = v2Encrypt(plaintext, "v2 synthetic", "another password");
  const material = await deriveLegacy(2, "v2 synthetic", "another password");
  assert.equal(hex(material.keyhash), v2.keyhash); assert.equal(hex(material.passhash), v2.passhash);
  assert.equal(detectLegacyFormat(v2.content), 2); assert.equal(await v2Decrypt(v2.content, material.passhash), plaintext);
  assert.equal((parseLegacyEntries(plaintext, 2))[0].note, "note");
  let wrong = ""; try { wrong = await v2Decrypt(v2.content, crypto.getRandomValues(new Uint8Array(32))); } catch { /* wrong AES-CTR credentials may fail UTF-8 decoding */ }
  assert.equal(await verifyPlaintext(wrong, shaHex(Buffer.from(plaintext))), false);
});

test("legacy parser accepts a large document while keeping field limits", () => {
  const plaintext = JSON.stringify(Array.from({ length: 400 }, (_, i) => ({ service: `service-${i}`, username: "user", password: "password", text: "note" })));
  assert.ok(plaintext.length > 16 * 1024);
  assert.equal(parseLegacyEntries(plaintext, 2).length, 400);
});

test("capsules are memory-hard, opaque, authenticated, and recover both formats", async () => {
  const created = 1700000000000, expires = created + 1000;
  for (const row of [v1Row, (() => { const v2 = v2Encrypt("[]", "v2 synthetic", "another password"); return { id: 2, keyhash: v2.keyhash, passhash: v2.passhash, contenthash: shaHex(Buffer.from("[]")), content: v2.content, accessed: v1Row.accessed, modified: v1Row.modified }; })()]) {
    const one = await buildCapsule(row, created, expires, argon, n => Uint8Array.from({ length: n }, (_, i) => i + 1));
    const two = await buildCapsule(row, created, expires, argon, n => Uint8Array.from({ length: n }, (_, i) => i + 2));
    assert.notDeepEqual(one.blob, two.blob); assert.equal(one.blob[0], 1); assert.equal(one.blob[1], one.format);
    const keyhash = Buffer.from(row.keyhash, "hex"), passhash = Buffer.from(row.passhash, "hex");
    const material = await deriveCapsuleMaterial(one.format, keyhash, passhash, argon);
    const capsule = await decryptCapsule(one.blob, material.wrapKey, one.format);
    assert.equal(capsule.contentHash, row.contenthash); assert.equal(capsule.content, row.content);
    const altered = one.blob.slice(); altered[altered.length - 1] ^= 1;
    await assert.rejects(() => decryptCapsule(altered, material.wrapKey, one.format));
    assert.doesNotMatch(Buffer.from(one.blob).toString("utf8"), /passhash|keyhash|contenthash/);
  }
});

test("converter strictly parses, verifies, and emits only import fields", async () => {
  const sql = `CREATE TABLE pages (id int, keyhash varchar(128), passhash varchar(128), contenthash varchar(128), content text, accessed datetime, modified datetime);\nINSERT INTO pages VALUES (${v1Row.id},'${v1Row.keyhash}','${v1Row.passhash}','${v1Row.contenthash}','${v1Row.content}','${v1Row.accessed}','${v1Row.modified}');`;
  const rows = parseLegacyDump(sql, 1); assert.equal(rows[0].content, v1Content);
  const result = await convertRows(rows, 1700000000000, 1800000000000);
  const output = result.records.map(row => JSON.stringify(row)).join("\n") + "\n";
  assert.equal(verifyCapsuleFile(output, 1).length, 1); assert.deepEqual(result.counts, { v1: 1, v2: 0 });
  assert.doesNotMatch(output, /keyhash|passhash|contenthash|plaintext/);
  const sqlImport = capsuleSql(output); assert.match(sqlImport, /INSERT INTO legacy_capsules/); assert.doesNotMatch(sqlImport, /keyhash|passhash|contenthash|plaintext/);
  assert.throws(() => parseLegacyDump(sql.replace("CREATE TABLE pages", "CREATE TABLE other"), 1));
});

test("recovered entries can be encrypted into and verified as a v3 vault", async () => {
  const keys = await deriveV3("new synthetic vault", "new master password", argon);
  const doc = { format: 1, entries: parseLegacyEntries(v1Plaintext, 1) };
  const blob = await encryptV3(doc, keys.encKey); assert.deepEqual(await decryptV3(blob, keys.encKey), doc);
  const wrong = keys.encKey.slice(); wrong[0] ^= 1; await assert.rejects(() => decryptV3(blob, wrong));
});
