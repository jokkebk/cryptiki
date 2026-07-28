const MAX_BLOB = 128 * 1024;
const MAX_BODY = 180 * 1024;
const MAX_RECOVERY_BODY = 1024;
const ID_RE = /^[0-9a-f]{32}$/;
const LOOKUP_ID_RE = /^[0-9a-f]{32}$/;
const ASSET_VERSION = "e89c024660c8e93e35c1e9074473d4b4a868e5ec5a2f27745482ac862ec62ebd";
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const HSTS = "max-age=31536000; includeSubDomains";

function headers(origin, requestUrl = "") {
  const h = new Headers(JSON_HEADERS);
  h.set("Cache-Control", "no-store");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Strict-Transport-Security", HSTS);
  h.set("Vary", "Origin");
  const sameOrigin = requestUrl && origin === new URL(requestUrl).origin;
  if (origin === "null" || sameOrigin || origin === "https://cryptiki.com") {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, If-None-Match");
    h.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  }
  return h;
}

function json(body, status, origin, requestUrl) {
  return new Response(JSON.stringify(body), { status, headers: headers(origin, requestUrl) });
}

function generic(origin, requestUrl) { return json({ error: "not available" }, 404, origin, requestUrl); }

async function allowed(limiter, key) {
  return !limiter || (await limiter.limit({ key })).success;
}

function edgeKey(request) {
  const ip = request.headers.get("CF-Connecting-IP");
  return ip ? `ip:${ip}` : "edge-identity-missing";
}

function validId(id) { return ID_RE.test(id); }

function fromB64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const text = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  try {
    const raw = atob(text);
    const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
    return bytes.length <= MAX_BLOB ? bytes : null;
  } catch { return null; }
}

function bearer(request) {
  const value = request.headers.get("Authorization") || "";
  const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(value);
  return match ? fromB64(match[1]) : null;
}

async function digest(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function sameBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
  return result === 0;
}

async function requestText(request, maxBytes) {
  const lengthHeader = request.headers.get("Content-Length");
  const length = lengthHeader === null ? 0 : Number(lengthHeader);
  if (lengthHeader !== null && (!Number.isSafeInteger(length) || length < 0 || length > maxBytes)) return null;
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { await reader.cancel(); return null; }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) { all.set(chunk, at); at += chunk.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(all); } catch { return null; }
}

async function bodyBlob(request) {
  if (request.headers.get("Content-Type") !== "application/json") return null;
  const text = await requestText(request, MAX_BODY);
  if (text === null) return null;
  try {
    const value = JSON.parse(text);
    const blob = fromB64(value?.blob);
    return blob && blob.length >= 29 && blob[0] === 1 ? blob : null;
  } catch { return null; }
}

async function findVault(env, id, auth) {
  const authHash = await digest(auth || new Uint8Array());
  const row = await env.DB.prepare("SELECT id, auth_hash, blob, rev, created, modified FROM vaults WHERE id = ?1")
    .bind(id).first();
  if (!row || !auth || !sameBytes(new Uint8Array(row.auth_hash), authHash)) return null;
  return row;
}

async function api(request, env, id) {
  const origin = request.headers.get("Origin") || "";
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(origin, request.url) });
  if (!validId(id)) return generic(origin, request.url);
  const auth = bearer(request);
  const actor = edgeKey(request);
  if (!await allowed(env.REQUEST_LIMITER, `api:${actor}`)) return json({ error: "try later" }, 429, origin, request.url);
  if (request.method === "POST") {
    if (!await allowed(env.CREATE_LIMITER, actor)) return json({ error: "try later" }, 429, origin, request.url);
    const existing = await env.DB.prepare("SELECT auth_hash FROM vaults WHERE id = ?1").bind(id).first();
    if (existing && (!auth || !sameBytes(new Uint8Array(existing.auth_hash), await digest(auth)))) return generic(origin, request.url);
    const blob = auth && request.headers.get("If-None-Match") === "*" ? await bodyBlob(request) : null;
    if (!auth || !blob) return generic(origin, request.url);
    const now = Date.now();
    const result = await env.DB.prepare("INSERT INTO vaults (id, auth_hash, blob, rev, created, modified) VALUES (?1, ?2, ?3, 1, ?4, ?4) ON CONFLICT(id) DO NOTHING")
      .bind(id, await digest(auth), blob, now).run();
    if (!result.meta.changes) return json({ error: "vault already exists" }, 409, origin, request.url);
    return json({ rev: 1 }, 201, origin, request.url);
  }
  if (!auth) return generic(origin, request.url);
  if (!await allowed(env.AUTH_LIMITER, `${actor}:${id}`)) return json({ error: "try later" }, 429, origin, request.url);
  const current = await findVault(env, id, auth);
  if (!current) return generic(origin, request.url);
  if (request.method === "GET") return json({ rev: current.rev, blob: toB64(new Uint8Array(current.blob)) }, 200, origin, request.url);
  if (request.method === "DELETE") {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM revisions WHERE id = ?1").bind(id),
      env.DB.prepare("DELETE FROM vaults WHERE id = ?1 AND auth_hash = ?2").bind(id, current.auth_hash)
    ]);
    return new Response(null, { status: 204, headers: headers(origin, request.url) });
  }
  if (request.method !== "PUT") return json({ error: "method not allowed" }, 405, origin, request.url);
  const expected = request.headers.get("If-Match");
  if (!/^\d+$/.test(expected || "") || Number(expected) !== current.rev) return json({ error: "revision conflict" }, 409, origin, request.url);
  const blob = await bodyBlob(request);
  if (!blob) return json({ error: "invalid blob" }, 400, origin, request.url);
  const now = Date.now();
  const results = await env.DB.batch([
    env.DB.prepare("INSERT INTO revisions (id, rev, blob, saved) SELECT id, rev, blob, ?2 FROM vaults WHERE id = ?1 AND auth_hash = ?3 AND rev = ?4").bind(id, now, current.auth_hash, current.rev),
    env.DB.prepare("UPDATE vaults SET blob = ?2, rev = rev + 1, modified = ?3 WHERE id = ?1 AND auth_hash = ?4 AND rev = ?5").bind(id, blob, now, current.auth_hash, current.rev),
    env.DB.prepare("DELETE FROM revisions WHERE id = ?1 AND rev < (SELECT rev - 10 FROM vaults WHERE id = ?1)").bind(id)
  ]);
  if (!results[1].meta.changes) return json({ error: "revision conflict" }, 409, origin, request.url);
  return json({ rev: current.rev + 1 }, 200, origin, request.url);
}

async function recoverLegacy(request, env) {
  const origin = request.headers.get("Origin") || "";
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(origin, request.url) });
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405, origin, request.url);
  const actor = edgeKey(request);
  if (!await allowed(env.REQUEST_LIMITER, `legacy:${actor}`)) return json({ error: "try later" }, 429, origin, request.url);
  if (!await allowed(env.AUTH_LIMITER, `legacy:${actor}`)) return json({ error: "try later" }, 429, origin, request.url);
  if (request.headers.get("Content-Type") !== "application/json") return generic(origin, request.url);
  let body;
  try {
    const text = await requestText(request, MAX_RECOVERY_BODY);
    if (text === null) return generic(origin, request.url);
    body = JSON.parse(text);
  } catch { return generic(origin, request.url); }
  const lookupId = body && body.lookupId;
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).length !== 1 || !LOOKUP_ID_RE.test(lookupId || "")) return generic(origin, request.url);
  const row = await env.DB.prepare("SELECT format, blob FROM legacy_capsules WHERE lookup_id = ?1 AND expires > ?2")
    .bind(lookupId, Date.now()).first();
  if (!row || (row.format !== 1 && row.format !== 2) || !row.blob) return generic(origin, request.url);
  const blob = new Uint8Array(row.blob);
  if (blob.length < 30 || blob[0] !== 1 || blob[1] !== row.format) return generic(origin, request.url);
  return json({ format: row.format, blob: toB64(blob) }, 200, origin, request.url);
}

function toB64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      /* Crypto APIs need a secure context, so plain HTTP is never usable here. */
      if (url.protocol === "http:") {
        url.protocol = "https:";
        const permanent = request.method === "GET" || request.method === "HEAD";
        return new Response(null, { status: permanent ? 301 : 308, headers: { Location: url.toString() } });
      }
      if (url.pathname === "/api/legacy/recover") return recoverLegacy(request, env);
      if (url.pathname.startsWith("/api/vaults/")) return api(request, env, url.pathname.slice(12));
      if (url.pathname.startsWith("/api/")) return new Response("Not found", { status: 404, headers: headers(request.headers.get("Origin") || "", request.url) });
      if (request.method !== "GET" && request.method !== "HEAD") return new Response("Not found", { status: 404 });
      const assetPath = url.pathname === "/" ? "/index.html" : (url.pathname === "/legacy-migration" || url.pathname === "/legacy-migration/") ? "/migrate" : url.pathname;
      const assetUrl = new URL(assetPath, request.url);
      assetUrl.searchParams.set("v", ASSET_VERSION);
      const assetRequest = new Request(assetUrl, request);
      const response = await env.ASSETS.fetch(assetRequest);
      /* Stale links (old /new.html and friends) land on the app instead of a typeless 404 the browser downloads. */
      if (response.status === 404) return new Response(null, { status: 302, headers: { Location: new URL("/", request.url).toString(), "Cache-Control": "no-store" } });
      const h = new Headers(response.headers);
      h.set("Cache-Control", "no-store");
      h.set("Strict-Transport-Security", HSTS);
      return new Response(response.body, { status: response.status, headers: h });
    } catch {
      return generic(request.headers.get("Origin") || "", request.url);
    }
  },
  async scheduled(_event, env) {
    if (env.DB) await env.DB.prepare("DELETE FROM legacy_capsules WHERE expires <= ?1").bind(Date.now()).run();
  }
};
