import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

const b64 = x => Buffer.from(x).toString("base64url");
const id = "0123456789abcdef0123456789abcdef";
const blob = Uint8Array.from({ length: 29 }, (_, i) => i + 1); blob[0] = 1;
class DB {
  constructor() { this.vaults = new Map(); this.revisions = []; this.legacyCapsules = new Map(); }
  prepare(sql) { return new Stmt(this, sql); }
  async batch(stmts) { return Promise.all(stmts.map(s => s.run())); }
}
class Stmt {
  constructor(db, sql) { this.db = db; this.sql = sql; this.args = []; }
  bind(...args) { this.args = args; return this; }
  async first() {
    if (this.sql.startsWith("SELECT format, blob FROM legacy_capsules")) { const row = this.db.legacyCapsules.get(this.args[0]); return row && row.expires > this.args[1] ? { format: row.format, blob: row.blob.slice() } : null; }
    const row = this.db.vaults.get(this.args[0]); return row ? { ...row, auth_hash: row.auth_hash.slice(), blob: row.blob.slice() } : null;
  }
  async run() {
    const [id, a, b, c, d] = this.args;
    if (this.sql.startsWith("INSERT INTO vaults")) { if (this.db.vaults.has(id)) return { meta: { changes: 0 } }; this.db.vaults.set(id, { id, auth_hash: a.slice(), blob: b.slice(), rev: 1, created: c, modified: c }); return { meta: { changes: 1 } }; }
    if (this.sql.startsWith("INSERT INTO revisions")) { const row = this.db.vaults.get(id); if (row && Buffer.from(row.auth_hash).equals(Buffer.from(b)) && row.rev === c) this.db.revisions.push({ id, rev: row.rev, blob: row.blob.slice(), saved: a }); return { meta: { changes: 1 } }; }
    if (this.sql.startsWith("UPDATE vaults")) { const row = this.db.vaults.get(id); if (!row || !Buffer.from(row.auth_hash).equals(Buffer.from(c)) || row.rev !== d) return { meta: { changes: 0 } }; row.blob = a.slice(); row.rev++; row.modified = b; return { meta: { changes: 1 } }; }
    if (this.sql.startsWith("DELETE FROM revisions WHERE id = ?1 AND rev <")) { const row = this.db.vaults.get(id); this.db.revisions = this.db.revisions.filter(x => x.id !== id || x.rev >= row.rev - 10); return { meta: { changes: 1 } }; }
    if (this.sql.startsWith("DELETE FROM legacy_capsules")) { this.db.legacyCapsules.delete(this.args[0]); return { meta: { changes: 1 } }; }
    if (this.sql.startsWith("DELETE FROM revisions")) { this.db.revisions = this.db.revisions.filter(x => x.id !== id); return { meta: { changes: 1 } }; }
    if (this.sql.startsWith("DELETE FROM vaults")) { const row = this.db.vaults.get(id); if (row && Buffer.from(row.auth_hash).equals(Buffer.from(a))) this.db.vaults.delete(id); return { meta: { changes: 1 } }; }
    return { meta: { changes: 0 } };
  }
}
const auth = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const other = Uint8Array.from({ length: 32 }, (_, i) => i + 2);
const request = (method, authorization = auth, headers = {}, body) => new Request(`https://preview.example/api/vaults/${id}`, { method, headers: { Origin: "null", ...(authorization && { Authorization: `Bearer ${b64(authorization)}` }), ...headers }, body: body && JSON.stringify(body) });
const env = () => ({ DB: new DB(), ASSETS: { fetch: () => new Response("app") } });

test("create is insert-only and all existing-vault operations authenticate", async () => {
  const e = env(); const make = await worker.fetch(request("POST", auth, { "If-None-Match": "*", "Content-Type": "application/json" }, { blob: b64(blob) }), e); assert.equal(make.status, 201);
  const hidden = await worker.fetch(request("POST", other, { "If-None-Match": "*", "Content-Type": "application/json" }, { blob: b64(Uint8Array.of(9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9)) }), e); assert.equal(hidden.status, 404);
  const replace = await worker.fetch(request("POST", auth, { "If-None-Match": "*", "Content-Type": "application/json" }, { blob: b64(blob) }), e); assert.equal(replace.status, 409);
  for (const method of ["GET", "PUT", "DELETE"]) { const r = await worker.fetch(request(method, other, method === "PUT" ? { "If-Match": "1", "Content-Type": "application/json" } : {}, method === "PUT" ? { blob: b64(blob) } : undefined), e); assert.equal(r.status, 404); }
  const read = await worker.fetch(request("GET", auth), e); assert.equal((await read.json()).blob, b64(blob));
});

test("malformed or missing bearer auth is generic and never crashes", async () => {
  const e = env(); await worker.fetch(request("POST", auth, { "If-None-Match": "*", "Content-Type": "application/json" }, { blob: b64(blob) }), e);
  for (const authorization of [null, new Uint8Array([1, 2, 3])]) {
    const r = await worker.fetch(request("GET", authorization), e);
    assert.equal(r.status, 404);
    assert.equal(r.headers.get("Access-Control-Allow-Origin"), "null");
  }
});

test("rate limits use the edge IP, run before D1, and enforce denial", async () => {
  const calls = [];
  const limiter = { limit: async ({ key }) => { calls.push(key); return { success: false }; } };
  const e = { ...env(), REQUEST_LIMITER: limiter };
  const r = await worker.fetch(request("GET", auth, { "CF-Connecting-IP": "203.0.113.10" }), e);
  assert.equal(r.status, 429);
  assert.deepEqual(calls, ["api:ip:203.0.113.10"]);
  assert.equal(e.DB.vaults.size, 0);
});

test("failed vault authentication is limited before its lookup", async () => {
  const calls = [];
  const limiter = { limit: async ({ key }) => { calls.push(key); return { success: calls.length < 2 }; } };
  const e = { ...env(), REQUEST_LIMITER: limiter, AUTH_LIMITER: limiter };
  const r = await worker.fetch(request("GET", other, { "CF-Connecting-IP": "203.0.113.11" }), e);
  assert.equal(r.status, 429);
  assert.deepEqual(calls, ["api:ip:203.0.113.11", "ip:203.0.113.11:0123456789abcdef0123456789abcdef"]);
});

test("CAS conflicts preserve data and pruning keeps ten revisions", async () => {
  const e = env(); await worker.fetch(request("POST", auth, { "If-None-Match": "*", "Content-Type": "application/json" }, { blob: b64(blob) }), e);
  const conflict = await worker.fetch(request("PUT", auth, { "If-Match": "0", "Content-Type": "application/json" }, { blob: b64(blob) }), e); assert.equal(conflict.status, 409);
  for (let i = 1; i <= 12; i++) { const nextBlob = Uint8Array.from({ length: 29 }, () => i); nextBlob[0] = 1; const r = await worker.fetch(request("PUT", auth, { "If-Match": String(i), "Content-Type": "application/json" }, { blob: b64(nextBlob) }), e); assert.equal(r.status, 200); }
  assert.equal(e.DB.revisions.length, 10); const stale = await worker.fetch(request("PUT", auth, { "If-Match": "1", "Content-Type": "application/json" }, { blob: b64(blob) }), e); assert.equal(stale.status, 409);
});

test("legacy recovery is read-only, opaque, expiring, and non-enumerable", async () => {
  const e = env(); const lookupId = "abcdefabcdefabcdefabcdefabcdefab"; const capsule = Uint8Array.from({ length: 30 }, (_, i) => i + 1); capsule[1] = 1;
  e.DB.legacyCapsules.set(lookupId, { format: 1, blob: capsule, expires: Date.now() + 60_000 });
  const recover = (method, value, extra = {}) => new Request("https://cryptiki.com/api/legacy/recover", { method, headers: { Origin: "null", ...(["POST", "DELETE"].includes(method) && { "Content-Type": "application/json" }), ...extra }, body: value && JSON.stringify(value) });
  const ok = await worker.fetch(recover("POST", { lookupId }), e); assert.equal(ok.status, 200); assert.equal((await ok.json()).format, 1); assert.equal(ok.headers.get("Access-Control-Allow-Origin"), "null");
  const consumed = await worker.fetch(recover("DELETE", { lookupId }), e); assert.equal(consumed.status, 204); assert.equal(e.DB.legacyCapsules.has(lookupId), false);
  const missing = await worker.fetch(recover("POST", { lookupId: "00000000000000000000000000000000" }), e); assert.equal(missing.status, 404);
  const expired = await worker.fetch(recover("POST", { lookupId }), { ...e, DB: (() => { const db = new DB(); db.legacyCapsules.set(lookupId, { format: 1, blob: capsule, expires: Date.now() - 1 }); return db; })() }); assert.equal(expired.status, 404);
  assert.equal((await worker.fetch(recover("GET", null), e)).status, 405);
  assert.equal((await worker.fetch(recover("POST", { lookupId }, { "Content-Type": "text/plain" }), e)).status, 404);
});

test("legacy recovery keys the limiter on CF-Connecting-IP", async () => {
  const calls = []; const e = { ...env(), REQUEST_LIMITER: { limit: async ({ key }) => { calls.push(key); return { success: true }; } }, AUTH_LIMITER: { limit: async ({ key }) => { calls.push(key); return { success: false }; } } };
  const recover = new Request("https://cryptiki.com/api/legacy/recover", { method: "POST", headers: { Origin: "null", "CF-Connecting-IP": "203.0.113.12", "Content-Type": "application/json" }, body: JSON.stringify({ lookupId: "abcdefabcdefabcdefabcdefabcdefab" }) });
  const r = await worker.fetch(recover, e); assert.equal(r.status, 429);
  assert.deepEqual(calls, ["legacy:ip:203.0.113.12", "legacy:ip:203.0.113.12"]);
});

test("chunked and malformed request bodies are bounded and rejected", async () => {
  const e = env();
  const oversized = new Request(`https://preview.example/api/vaults/${id}`, { method: "POST", headers: { Origin: "null", Authorization: `Bearer ${b64(auth)}`, "If-None-Match": "*", "Content-Type": "application/json" }, body: JSON.stringify({ blob: b64(new Uint8Array(128 * 1024)) }) });
  assert.equal((await worker.fetch(oversized, e)).status, 404);
  const invalidBlob = await worker.fetch(request("POST", auth, { "If-None-Match": "*", "Content-Type": "application/json" }, { blob: b64(Uint8Array.of(1, 2, 3)) }), e);
  assert.equal(invalidBlob.status, 404);
});

test("scheduled cleanup deletes expired capsules", async () => {
  const e = env(); const expired = "abcdefabcdefabcdefabcdefabcdefab";
  e.DB.legacyCapsules.set(expired, { format: 1, blob: Uint8Array.of(1), expires: Date.now() - 1 });
  let deleted = false; e.DB.prepare = sql => ({ bind: () => ({ run: async () => { deleted = sql.includes("DELETE FROM legacy_capsules"); return { meta: { changes: 1 } }; } }) });
  await worker.scheduled({}, e); assert.equal(deleted, true);
});

test("plain HTTP redirects to HTTPS and unknown paths land on the app", async () => {
  const e = { DB: new DB(), ASSETS: { fetch: url => new Response(new URL(url.url).pathname === "/index.html" ? "app" : null, { status: new URL(url.url).pathname === "/index.html" ? 200 : 404 }) } };
  const insecure = await worker.fetch(new Request("http://cryptiki.com/"), e);
  assert.equal(insecure.status, 301); assert.equal(insecure.headers.get("Location"), "https://cryptiki.com/");
  const insecurePost = await worker.fetch(new Request("http://cryptiki.com/api/vaults/" + id, { method: "POST" }), e);
  assert.equal(insecurePost.status, 308);
  const stale = await worker.fetch(new Request("https://cryptiki.com/new.html"), e);
  assert.equal(stale.status, 302); assert.equal(stale.headers.get("Location"), "https://cryptiki.com/");
  const root = await worker.fetch(new Request("https://cryptiki.com/"), e);
  assert.equal(root.status, 200); assert.equal(root.headers.get("Strict-Transport-Security"), "max-age=31536000; includeSubDomains");
  const apiTypo = await worker.fetch(new Request("https://cryptiki.com/api/typo"), e);
  assert.equal(apiTypo.status, 404);
});
