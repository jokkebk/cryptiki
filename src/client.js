/* Cryptiki v3 browser client. Secrets live only in this closure and memory. */
const API = (location.protocol === "file:" ? "https://cryptiki.com" : "").replace(/\/$/, "");
const VERSION = "3.0.0-preview";
const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = id => document.getElementById(id);
const text = value => typeof value === "string" ? value : "";
const bytes = value => value instanceof Uint8Array ? value : new Uint8Array(value);
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; };
const hex = value => [...value].map(x => x.toString(16).padStart(2, "0")).join("");
const b64 = value => { let s = ""; for (let i = 0; i < value.length; i += 0x8000) s += String.fromCharCode(...value.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64 = value => { const s = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4); const raw = atob(s); return Uint8Array.from(raw, c => c.charCodeAt(0)); };

async function sha(value) { return bytes(await crypto.subtle.digest("SHA-256", value)); }
async function hkdf(key, salt, info) {
  const imported = await crypto.subtle.importKey("raw", key, "HKDF", false, ["deriveBits"]);
  return bytes(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, imported, 256));
}
async function derive(name, password, progress) {
  const nameSalt = await sha(cat(enc.encode("cryptiki.v3.vault-salt\0"), enc.encode(name)));
  const root = await window.argon2idAsync(enc.encode(password), nameSalt, { m: 65536, t: 3, p: 1, dkLen: 32, maxmem: 70 * 1024 * 1024, asyncTick: 20, onProgress: progress });
  const [encKey, auth, idBytes] = await Promise.all([
    hkdf(root, nameSalt, enc.encode("cryptiki.v3.encryption")),
    hkdf(root, nameSalt, enc.encode("cryptiki.v3.authorization")),
    hkdf(root, nameSalt, enc.encode("cryptiki.v3.identifier")).then(x => x.subarray(0, 16))
  ]);
  return { name, password, nameSalt, root, encKey, auth, id: hex(idBytes) };
}
async function streamBytes(input, kind) {
  const stream = new Blob([input]).stream().pipeThrough(new kind());
  return bytes(await new Response(stream).arrayBuffer());
}
function validDocument(doc) {
  if (!doc || doc.format !== 1 || !Array.isArray(doc.entries) || doc.entries.length > 1000) throw Error("Invalid vault document");
  for (const e of doc.entries) if (!e || typeof e.id !== "string" || typeof e.service !== "string" || typeof e.username !== "string" || typeof e.password !== "string" || typeof e.note !== "string") throw Error("Invalid vault entry");
  return doc;
}
async function encrypt(doc, key) {
  validDocument(doc);
  const compressed = await streamBytes(enc.encode(JSON.stringify(doc)), CompressionStream.bind(null, "deflate-raw"));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const version = Uint8Array.of(1);
  const aad = cat(enc.encode("cryptiki.v3.blob\0"), version);
  const ciphertext = bytes(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, aes, compressed));
  return cat(version, nonce, ciphertext);
}
async function decrypt(blob, key) {
  if (blob.length < 29 || blob[0] !== 1) throw Error("Invalid encrypted vault");
  const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  const aad = cat(enc.encode("cryptiki.v3.blob\0"), Uint8Array.of(1));
  const compressed = bytes(await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(1, 13), additionalData: aad, tagLength: 128 }, aes, blob.subarray(13)));
  return validDocument(JSON.parse(dec.decode(await streamBytes(compressed, DecompressionStream.bind(null, "deflate-raw")))));
}
function emptyDocument() { return { format: 1, entries: [] }; }

const state = { keys: null, doc: null, rev: 0, selected: null, dirty: false, lockTimer: 0, hiddenAt: 0 };
function status(message, error = false) { $("status").textContent = message; $("status").className = error ? "error" : ""; }
function busy(value) { document.body.classList.toggle("busy", value); $("unlock").disabled = value; $("create").disabled = value; }
function showEditor(value) { $("unlock-screen").hidden = value; $("editor-screen").hidden = !value; }
function touch() { clearTimeout(state.lockTimer); state.lockTimer = setTimeout(lock, 15 * 60 * 1000); }
function lock() {
  clearTimeout(state.lockTimer);
  for (const key of ["root", "encKey", "auth", "nameSalt"]) state.keys?.[key]?.fill?.(0);
  if (state.keys) { state.keys.password = ""; state.keys.name = ""; }
  state.keys = null; state.doc = null; state.rev = 0; state.selected = null; state.dirty = false;
  for (const id of ["name", "master-password", "service", "username", "entry-password", "note", "search"]) $(id).value = "";
  showEditor(false); renderEntries(); status("Locked"); $("name").focus();
}
function markDirty() { state.dirty = true; $("save").textContent = "Save changes"; touch(); }
function renderEntries() {
  const list = $("entries"); list.replaceChildren();
  const needle = $("search").value.trim().toLowerCase();
  const entries = (state.doc?.entries || []).filter(e => !needle || [e.service, e.username, e.note].some(v => v.toLowerCase().includes(needle)));
  $("count").textContent = `${entries.length} / ${state.doc?.entries?.length || 0}`;
  for (const entry of entries) {
    const row = document.createElement("article"); row.className = "entry";
    const title = document.createElement("strong"); title.textContent = entry.service || "(unnamed)";
    const meta = document.createElement("span"); meta.textContent = entry.username;
    const edit = button("Edit", () => editEntry(entry.id));
    const copyUser = button("Copy username", () => copySecret(entry.username, copyUser));
    const copy = button("Copy password", () => copySecret(entry.password, copy));
    row.append(title, meta, edit, copyUser, copy); list.append(row);
  }
}
function button(label, action) { const b = document.createElement("button"); b.type = "button"; b.className = "secondary"; b.textContent = label; b.addEventListener("click", action); return b; }
function editEntry(id) {
  state.selected = id;
  const e = state.doc.entries.find(x => x.id === id);
  $("service").value = e?.service || ""; $("username").value = e?.username || ""; $("entry-password").value = e?.password || ""; $("note").value = e?.note || ""; $("service").focus();
}
function newEntry() { state.selected = crypto.randomUUID(); $("service").value = ""; $("username").value = ""; $("entry-password").value = ""; $("note").value = ""; $("service").focus(); }
function saveEntry() {
  if (!state.doc) return;
  const entry = { id: state.selected || crypto.randomUUID(), service: $("service").value.trim(), username: $("username").value, password: $("entry-password").value, note: $("note").value };
  if (!entry.service) return status("Service is required", true);
  const old = state.doc.entries.findIndex(e => e.id === entry.id); if (old < 0) state.doc.entries.push(entry); else state.doc.entries[old] = entry;
  state.selected = entry.id; markDirty(); renderEntries(); status("Unsaved changes");
}
function deleteEntry() { const i = state.doc?.entries.findIndex(e => e.id === state.selected); if (i < 0) return; if (!confirm("Delete this entry?")) return; state.doc.entries.splice(i, 1); state.selected = null; markDirty(); renderEntries(); status("Unsaved changes"); }
async function api(method, path, headers = {}, body) {
  const h = new Headers(headers); if (state.keys) h.set("Authorization", `Bearer ${b64(state.keys.auth)}`); if (body) h.set("Content-Type", "application/json");
  return fetch(`${API}/api/vaults/${path}`, { method, headers: h, body: body && JSON.stringify(body), cache: "no-store" });
}
async function unlock(create) {
  const name = $("name").value.trim(), password = $("master-password").value;
  if (!name || !password) return status("Enter a vault name and master password", true);
  busy(true); status("Deriving key (this takes a moment)…");
  try {
    const keys = await derive(name, password, p => { $("progress").value = p; }); state.keys = keys;
    const response = await api("GET", keys.id);
    if (response.ok) { const data = await response.json(); state.doc = await decrypt(unb64(data.blob), keys.encKey); state.rev = data.rev; }
    else if (response.status === 404 && create) { state.doc = emptyDocument(); const blob = await encrypt(state.doc, keys.encKey); const made = await api("POST", keys.id, { "If-None-Match": "*" }, { blob: b64(blob) }); if (!made.ok) throw Error(made.status === 409 ? "That vault already exists" : "Vault creation failed"); state.rev = 1; }
    else { state.keys = null; throw Error(response.status === 404 ? "Vault not found or credentials are wrong" : "Unlock failed"); }
    showEditor(true); renderEntries(); newEntry(); touch(); status("Saved"); $("search").focus();
  } catch (error) { lock(); status(error.message || "Unlock failed", true); }
  finally { busy(false); $("progress").value = 0; }
}
async function saveVault() {
  if (!state.keys || !state.doc) return;
  busy(true); status("Encrypting…");
  try {
    const blob = await encrypt(state.doc, state.keys.encKey);
    const response = state.rev ? await api("PUT", state.keys.id, { "If-Match": String(state.rev) }, { blob: b64(blob) }) : await api("POST", state.keys.id, { "If-None-Match": "*" }, { blob: b64(blob) });
    if (response.status === 409) return showConflict(blob);
    if (!response.ok) throw Error("Save failed");
    state.rev = (await response.json()).rev; state.dirty = false; status(`Saved revision ${state.rev}`); $("save").textContent = "Save";
  } catch (error) { status(error.message || "Save failed", true); } finally { busy(false); }
}
async function showConflict(mine) {
  status("Conflict: someone saved a newer revision", true); $("conflict").hidden = false;
  $("reload-theirs").onclick = async () => { const r = await api("GET", state.keys.id); if (!r.ok) return status("Could not reload", true); const d = await r.json(); state.doc = await decrypt(unb64(d.blob), state.keys.encKey); state.rev = d.rev; state.dirty = false; $("conflict").hidden = true; renderEntries(); status("Reloaded their revision"); };
  $("download-mine").onclick = () => download("cryptiki-v3-conflict.json", JSON.stringify({ format: 1, blob: b64(mine) }));
}
async function copySecret(value, source) { try { await navigator.clipboard.writeText(value); source.textContent = "Copied"; setTimeout(() => source.textContent = "Copy password", 1500); setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 15000); } catch { status("Clipboard unavailable", true); } }
function generate() { const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_"; const random = crypto.getRandomValues(new Uint8Array(24)); $("entry-password").value = [...random].map(x => alphabet[x % alphabet.length]).join(""); markDirty(); }
function download(name, content) { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], { type: "application/octet-stream" })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
async function exportVault() { const salt = crypto.getRandomValues(new Uint8Array(16)); const key = await hkdf(state.keys.root, salt, enc.encode("cryptiki.v3.export")); const blob = await encrypt(state.doc, key); download("cryptiki-v3-export.json", JSON.stringify({ format: 1, salt: b64(salt), blob: b64(blob) }, null, 2)); }
async function importVault() { const raw = prompt("Paste a Cryptiki v3 export JSON"); if (!raw) return; try { const data = JSON.parse(raw); const key = await hkdf(state.keys.root, unb64(data.salt), enc.encode("cryptiki.v3.export")); state.doc = await decrypt(unb64(data.blob), key); state.selected = null; markDirty(); renderEntries(); status("Imported; save to sync"); } catch { status("Import failed or export credentials differ", true); } }
async function changeCredentials() {
  const enteredName = prompt("New vault name (blank keeps current)", state.keys.name); if (enteredName === null) return;
  const enteredPassword = prompt("New master password (blank keeps current)"); if (enteredPassword === null) return;
  const name = enteredName.trim() || state.keys.name; const password = enteredPassword || state.keys.password;
  busy(true); status("Creating the new vault…"); const old = state.keys;
  try { const next = await derive(name.trim(), password); const blob = await encrypt(state.doc, next.encKey); const made = await apiWith("POST", next.id, next.auth, { "If-None-Match": "*" }, { blob: b64(blob) }); if (!made.ok) throw Error("New credentials already exist or could not be created"); const check = await apiWith("GET", next.id, next.auth); const verified = await check.json(); await decrypt(unb64(verified.blob), next.encKey); const removed = await apiWith("DELETE", old.id, old.auth); if (!removed.ok && removed.status !== 204) { state.keys = next; state.rev = verified.rev; return status("Both vaults exist; retry deletion of the old vault", true); } state.keys = next; state.rev = 1; state.dirty = false; $("name").value = name; status("Credentials changed"); }
  catch (error) { status(error.message || "Credential change failed", true); } finally { busy(false); }
}
async function apiWith(method, id, auth, headers = {}, body) { const h = new Headers(headers); h.set("Authorization", `Bearer ${b64(auth)}`); if (body) h.set("Content-Type", "application/json"); return fetch(`${API}/api/vaults/${id}`, { method, headers: h, body: body && JSON.stringify(body), cache: "no-store" }); }
function saveApp() { download("cryptiki-v3.html", `<!doctype html>\n${document.documentElement.outerHTML}`); }
function pageHash() { const html = document.documentElement.outerHTML.replace(/(<code id="page-hash">)[^<]*/, "$1"); sha(enc.encode(html)).then(x => $("page-hash").textContent = hex(x)); }
window.addEventListener("DOMContentLoaded", () => {
  $("version").textContent = VERSION; $("unlock").onclick = () => unlock(false); $("create").onclick = () => unlock(true); $("lock").onclick = lock; $("new-entry").onclick = newEntry; $("save-entry").onclick = saveEntry; $("delete-entry").onclick = deleteEntry; $("generate").onclick = generate; $("save").onclick = saveVault; $("export").onclick = exportVault; $("import").onclick = importVault; $("change").onclick = changeCredentials; $("save-app").onclick = saveApp; $("search").oninput = renderEntries; $("dismiss").onclick = () => $("notice").hidden = true; $("name").focus(); pageHash();
  document.addEventListener("keydown", touch); document.addEventListener("visibilitychange", () => { if (document.hidden) state.hiddenAt = Date.now(); else if (state.hiddenAt && Date.now() - state.hiddenAt > 60_000) lock(); else touch(); }); window.addEventListener("beforeunload", e => { if (state.dirty) { e.preventDefault(); e.returnValue = ""; } });
});
