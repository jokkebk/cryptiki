/* Cryptiki v3 browser client. Secrets live only in this closure and memory. */
const API = (location.protocol === "file:" ? "https://cryptiki.com" : "").replace(/\/$/, "");
const VERSION = "3.0.0";
const enc = new TextEncoder();
const dec = new TextDecoder();
const MAX_ENTRIES = 1000;
const MAX_STRING = 16 * 1024;
const MAX_DOCUMENT_BYTES = 512 * 1024;
const MAX_BLOB = 128 * 1024;
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
async function streamBytes(input, kind, maxBytes = Number.MAX_SAFE_INTEGER) {
  const stream = new Blob([input]).stream().pipeThrough(new kind());
  const reader = stream.getReader(); const chunks = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) { await reader.cancel(); throw Error("Vault document is too large"); }
    chunks.push(value);
  }
  const out = new Uint8Array(total); let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.byteLength; }
  return out;
}
function validDocument(doc) {
  if (!doc || doc.format !== 1 || !Array.isArray(doc.entries) || doc.entries.length > MAX_ENTRIES) throw Error("Invalid vault document");
  const ids = new Set();
  for (const e of doc.entries) {
    if (!e || typeof e.id !== "string" || typeof e.service !== "string" || typeof e.username !== "string" || typeof e.password !== "string" || typeof e.note !== "string") throw Error("Invalid vault entry");
    if (e.id.length > 256 || ids.has(e.id)) throw Error("Invalid vault entry");
    ids.add(e.id);
    for (const value of [e.service, e.username, e.password, e.note]) if (value.length > MAX_STRING) throw Error("Vault field is too long");
  }
  if (enc.encode(JSON.stringify(doc)).length > MAX_DOCUMENT_BYTES) throw Error("Vault document is too large");
  return doc;
}
async function encrypt(doc, key) {
  validDocument(doc);
  const compressed = await streamBytes(enc.encode(JSON.stringify(doc)), CompressionStream.bind(null, "deflate-raw"), MAX_BLOB - 29);
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
  return validDocument(JSON.parse(dec.decode(await streamBytes(compressed, DecompressionStream.bind(null, "deflate-raw"), MAX_DOCUMENT_BYTES))));
}
function emptyDocument() { return { format: 1, entries: [] }; }

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_";
const state = { keys: null, doc: null, rev: 0, dirty: false, lockTimer: 0, hiddenAt: 0, showAll: false, fresh: new Set(), openNotes: new Set(), rotation: null };
function status(message, error = false) { $("status").textContent = message; $("status").className = error ? "error" : ""; }
function busy(value) { document.body.classList.toggle("busy", value); $("unlock").disabled = value; $("create").disabled = value; }
function showEditor(value) { $("unlock-screen").hidden = value; $("editor-screen").hidden = !value; }
function touch() { clearTimeout(state.lockTimer); state.lockTimer = setTimeout(lock, 15 * 60 * 1000); }
function lock() {
  clearTimeout(state.lockTimer);
  for (const key of ["root", "encKey", "auth", "nameSalt"]) state.keys?.[key]?.fill?.(0);
  if (state.keys) { state.keys.password = ""; state.keys.name = ""; }
  for (const keySet of [state.rotation?.old, state.rotation?.next]) for (const key of ["root", "encKey", "auth", "nameSalt"]) keySet?.[key]?.fill?.(0);
  state.keys = null; state.doc = null; state.rev = 0; state.dirty = false; state.rotation = null;
  $("retry-old-delete").hidden = true;
  state.showAll = false; state.fresh.clear(); state.openNotes.clear();
  for (const id of ["name", "master-password", "create-confirm", "search"]) $(id).value = "";
  showEditor(false); renderEntries(); status("Locked"); $("name").focus();
}
function markDirty() { state.dirty = true; $("save").textContent = "Save changes"; status("Unsaved changes", false); $("status").className = "warn"; touch(); }
function toast(message) { const t = $("toast"); t.textContent = message; t.classList.add("up"); clearTimeout(t.timer); t.timer = setTimeout(() => t.classList.remove("up"), 1500); }
const SVG_NS = "http://www.w3.org/2000/svg";
/* Icons are built as nodes, never parsed from markup strings. */
function sprite(name) {
  const svg = document.createElementNS(SVG_NS, "svg"); const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", "#i-" + name); svg.append(use); return svg;
}
function el(tag, text, cls) { const node = document.createElement(tag); if (text) node.textContent = text; if (cls) node.className = cls; return node; }
function icon(name, label, cls, action) {
  const b = document.createElement("button"); b.type = "button"; b.className = "icon" + (cls ? " " + cls : "");
  b.setAttribute("aria-label", label); b.title = label;
  b.append(sprite(name)); b.addEventListener("click", action); return b;
}
/* Every value on screen is a live field; edits land in the document and wait for Save. */
function field(cls, value, placeholder, label, apply) {
  const input = document.createElement("input"); input.className = "f " + cls; input.value = value;
  input.placeholder = placeholder; input.setAttribute("aria-label", label); input.autocomplete = "off"; input.spellcheck = false;
  input.addEventListener("input", () => { apply(input.value); markDirty(); });
  return input;
}
function visibleEntries() {
  const needle = $("search").value.trim().toLowerCase();
  const all = state.doc?.entries || [];
  const found = needle ? all.filter(e => [e.service, e.username, e.note].some(v => v.toLowerCase().includes(needle)))
    : state.showAll ? all.slice() : all.filter(e => state.fresh.has(e.id));
  return found.sort((a, b) => a.service.localeCompare(b.service, "fi"));
}
function renderCount(shown) {
  const total = state.doc?.entries?.length || 0;
  const filtered = $("search").value.trim() || state.showAll;
  $("count").replaceChildren(el("b", String(filtered ? shown : total)),
    document.createTextNode(filtered ? ` shown of ${total}` : total === 1 ? " entry" : " entries"));
  $("toggle-all").textContent = state.showAll ? "Hide all" : "Show all";
  $("clear-search").hidden = !$("search").value;
}
function renderEntries() {
  const list = $("entries"); list.replaceChildren();
  const found = visibleEntries(); renderCount(found.length);
  const needle = $("search").value.trim();
  $("empty").hidden = found.length > 0;
  if (!found.length) {
    $("empty").querySelector(".big").textContent = needle ? `Nothing matches “${needle}”.` : "Nothing on screen — by design.";
    $("empty-hint").replaceChildren(...(needle
      ? [document.createTextNode("Try a shorter query, or "), el("b", "Show all"), document.createTextNode(".")]
      : [document.createTextNode("Type to find an entry. "), el("kbd", "/"), document.createTextNode(" focuses search, "),
         el("kbd", "Enter"), document.createTextNode(" copies the top match's password.")]));
    return;
  }
  const frag = document.createDocumentFragment();
  for (const entry of found) frag.append(entryRow(entry));
  list.append(frag);
}
function entryRow(entry) {
  const row = document.createElement("article"); row.className = "entry" + (state.fresh.has(entry.id) ? " fresh" : "");

  const svc = document.createElement("div"); svc.className = "cell c-svc";
  svc.append(field("svc", entry.service, "Service name", "Service", v => entry.service = v));

  const usr = document.createElement("div"); usr.className = "cell c-usr";
  usr.append(field("usr", entry.username, "no username", "Username", v => entry.username = v),
    icon("copy", "Copy username", "", event => copySecret(entry.username, event.currentTarget, "Username")));

  const pwCell = document.createElement("div"); pwCell.className = "cell c-pw";
  const password = field("pw", entry.password, "no password", "Password", v => entry.password = v); password.type = "password";
  const reveal = show => {
    password.type = show ? "text" : "password";
    eye.querySelector("use").setAttribute("href", show ? "#i-eye-off" : "#i-eye");
    eye.classList.toggle("on", show); row.classList.toggle("pw-open", show);
  };
  const eye = icon("eye", "Reveal password", "", () => { const show = password.type === "password"; reveal(show); if (show) password.focus({ preventScroll: true }); });
  pwCell.append(password, eye,
    icon("gen", "Generate a new password", "", () => {
      const random = crypto.getRandomValues(new Uint8Array(24));
      password.value = [...random].map(x => ALPHABET[x % ALPHABET.length]).join("");
      entry.password = password.value; reveal(true); markDirty(); toast("Password generated — not saved yet");
    }),
    icon("copy", "Copy password", "", event => copySecret(entry.password, event.currentTarget, "Password")));

  const noteCell = document.createElement("div"); noteCell.className = "cell c-note";
  const noteButton = icon(entry.note ? "note" : "note-empty", entry.note ? "Note — open it" : "No note — add one",
    entry.note ? "has-note" : "", () => toggleNote(entry, row, noteButton));
  noteCell.append(noteButton);

  const killCell = document.createElement("div"); killCell.className = "cell c-kill";
  killCell.append(icon("trash", "Delete entry", "kill", () => {
    if (!confirm(`Delete “${entry.service || "unnamed entry"}”?`)) return;
    const at = state.doc.entries.indexOf(entry); if (at < 0) return;
    state.doc.entries.splice(at, 1); state.fresh.delete(entry.id); state.openNotes.delete(entry.id);
    row.remove(); renderCount(visibleEntries().length); markDirty(); toast("Entry deleted — save to sync");
  }));

  row.append(svc, usr, pwCell, noteCell, killCell);
  if (state.openNotes.has(entry.id)) row.append(noteField(entry, noteButton));
  return row;
}
/* The note opens in place rather than re-rendering, so revealed passwords and focus survive. */
function toggleNote(entry, row, noteButton) {
  const open = row.querySelector(".note-wrap");
  if (open) { open.remove(); state.openNotes.delete(entry.id); return; }
  state.openNotes.add(entry.id);
  const wrap = noteField(entry, noteButton); row.append(wrap); wrap.querySelector("textarea").focus();
}
function noteField(entry, noteButton) {
  const wrap = document.createElement("div"); wrap.className = "note-wrap";
  const area = document.createElement("textarea"); area.value = entry.note;
  area.placeholder = "Recovery codes, security answers, account numbers…";
  area.setAttribute("aria-label", "Note for " + (entry.service || "entry"));
  area.addEventListener("input", () => {
    const had = !!entry.note; entry.note = area.value; markDirty();
    if (had !== !!area.value) {
      noteButton.classList.toggle("has-note", !!area.value);
      noteButton.querySelector("use").setAttribute("href", area.value ? "#i-note" : "#i-note-empty");
      noteButton.title = area.value ? "Note — open it" : "No note — add one";
    }
  });
  wrap.append(area); return wrap;
}
function newEntry() {
  if (!state.doc) return;
  const entry = { id: crypto.randomUUID(), service: "", username: "", password: "", note: "" };
  state.doc.entries.push(entry); state.fresh.add(entry.id); $("search").value = "";
  markDirty(); renderEntries(); document.querySelector(".entry.fresh .f.svc")?.focus();
}
function applyTheme(mode) {
  document.documentElement.dataset.theme = mode;
  $("theme").querySelector("use").setAttribute("href", mode === "dark" ? "#i-sun" : "#i-moon");
}
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
    else if (response.status === 404 && create) { if ($("create-confirm").value !== password) throw Error("Enter the same password twice to create a vault"); state.doc = emptyDocument(); const blob = await encrypt(state.doc, keys.encKey); const made = await api("POST", keys.id, { "If-None-Match": "*" }, { blob: b64(blob) }); if (!made.ok) throw Error(made.status === 409 ? "That vault already exists" : "Vault creation failed"); state.rev = 1; }
    else { state.keys = null; throw Error(response.status === 404 ? "Vault not found or credentials are wrong" : "Unlock failed"); }
    showEditor(true); renderEntries(); touch(); status(`Unlocked · revision ${state.rev}`); $("search").focus();
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
    if (!response.ok) throw Error(response.status === 400 ? "Vault document is too large or invalid" : "Save failed");
    state.rev = (await response.json()).rev; state.dirty = false; state.fresh.clear();
    status(`Saved revision ${state.rev}`); $("save").textContent = "Save"; renderEntries();
  } catch (error) { status(error.message || "Save failed", true); } finally { busy(false); }
}
async function showConflict(mine) {
  status("Conflict: someone saved a newer revision", true); $("conflict").hidden = false;
  $("reload-theirs").onclick = async () => { const r = await api("GET", state.keys.id); if (!r.ok) return status("Could not reload", true); const d = await r.json(); state.doc = await decrypt(unb64(d.blob), state.keys.encKey); state.rev = d.rev; state.dirty = false; $("conflict").hidden = true; renderEntries(); status("Reloaded their revision"); };
  $("download-mine").onclick = () => exportVault(mine, "cryptiki-v3-conflict.json");
}
async function copySecret(value, source, label) {
  if (!value) return toast(`No ${label.toLowerCase()} to copy`);
  try {
    await navigator.clipboard.writeText(value);
    toast(`${label} copied — best-effort clipboard clear in 15 s`);
    if (source) {
      const use = source.querySelector("use"); use.setAttribute("href", "#i-check"); source.classList.add("ok");
      setTimeout(() => { use.setAttribute("href", "#i-copy"); source.classList.remove("ok"); }, 1200);
    }
    setTimeout(async () => { try { if (navigator.clipboard.readText && await navigator.clipboard.readText() === value) await navigator.clipboard.writeText(""); } catch {} }, 15000);
  } catch { status("Clipboard unavailable", true); }
}
function download(name, content) { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], { type: "application/octet-stream" })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
async function exportVault(doc = state.doc, filename = "cryptiki-v3-export.json") { const salt = crypto.getRandomValues(new Uint8Array(16)); const key = await hkdf(state.keys.root, salt, enc.encode("cryptiki.v3.export")); const blob = await encrypt(doc, key); download(filename, JSON.stringify({ format: 1, salt: b64(salt), blob: b64(blob) }, null, 2)); }
async function importVault() { const raw = prompt("Paste a Cryptiki v3 export JSON"); if (!raw) return; try { const data = JSON.parse(raw); if (data?.format !== 1) throw Error(); const salt = unb64(data.salt); if (salt.length !== 16) throw Error(); const key = await hkdf(state.keys.root, salt, enc.encode("cryptiki.v3.export")); state.doc = await decrypt(unb64(data.blob), key); state.fresh.clear(); state.openNotes.clear(); markDirty(); renderEntries(); status("Imported; save to sync"); } catch { status("Import failed or export credentials differ", true); } }
async function changeCredentials() {
  $("credential-dialog").showModal(); $("new-credential-name").value = state.keys.name; $("new-credential-password").value = ""; $("new-credential-confirm").value = ""; $("new-credential-password").focus();
}
async function rotateCredentials(event) {
  event.preventDefault(); const name = $("new-credential-name").value.trim(), password = $("new-credential-password").value, confirmation = $("new-credential-confirm").value;
  if (!name || !password || password !== confirmation) return status("Enter matching new credentials", true);
  busy(true); status("Creating and verifying the new vault…"); const old = state.keys;
  try {
    if (name === old.name && password === old.password) throw Error("Choose a different credential");
    const next = await derive(name, password); const blob = await encrypt(state.doc, next.encKey);
    const made = await apiWith("POST", next.id, next.auth, { "If-None-Match": "*" }, { blob: b64(blob) });
    if (!made.ok && made.status !== 409) throw Error("New vault could not be created");
    const check = await apiWith("GET", next.id, next.auth); if (!check.ok) throw Error("New vault verification failed");
    const verified = await check.json(); const checkedDoc = await decrypt(unb64(verified.blob), next.encKey);
    if (JSON.stringify(checkedDoc) !== JSON.stringify(state.doc)) throw Error("New vault verification failed");
    const removed = await apiWith("DELETE", old.id, old.auth);
    if (!removed.ok && removed.status !== 204) { state.rotation = { old, next, rev: verified.rev }; $("retry-old-delete").hidden = false; status("New vault verified; delete the old vault to finish rotation", true); return; }
    state.keys = next; state.rev = verified.rev; state.dirty = false; $("name").value = name; $("retry-old-delete").hidden = true; status("Credentials changed");
  } catch (error) { status(error.message || "Credential change failed", true); } finally { busy(false); $("credential-dialog").close(); }
}
async function retryOldDeletion() {
  const pending = state.rotation; if (!pending) return;
  busy(true); status("Deleting the old vault…");
  try { const removed = await apiWith("DELETE", pending.old.id, pending.old.auth); if (!removed.ok && removed.status !== 204) throw Error("Old vault deletion failed; retry later"); state.keys = pending.next; state.rev = pending.rev; state.rotation = null; $("name").value = pending.next.name; $("retry-old-delete").hidden = true; status("Credentials changed; old vault deleted"); }
  catch (error) { status(error.message, true); } finally { busy(false); }
}
async function deleteCurrentVault() {
  if (!state.keys || prompt("Type DELETE to permanently remove this vault") !== "DELETE") return;
  busy(true); status("Deleting vault…");
  try { const response = await api("DELETE", state.keys.id); if (!response.ok && response.status !== 204) throw Error("Vault deletion failed"); lock(); status("Vault deleted"); }
  catch (error) { status(error.message, true); } finally { busy(false); }
}
async function apiWith(method, id, auth, headers = {}, body) { const h = new Headers(headers); h.set("Authorization", `Bearer ${b64(auth)}`); if (body) h.set("Content-Type", "application/json"); return fetch(`${API}/api/vaults/${id}`, { method, headers: h, body: body && JSON.stringify(body), cache: "no-store" }); }
/* Serialise a blank copy: rendered rows carry service names in aria-labels, so strip the list first. */
function saveApp() {
  const clone = document.documentElement.cloneNode(true);
  clone.querySelector("#entries").replaceChildren();
  clone.querySelector("#conflict").setAttribute("hidden", "");
  clone.querySelector("#editor-screen").setAttribute("hidden", "");
  clone.querySelector("#unlock-screen").removeAttribute("hidden");
  for (const el of clone.querySelectorAll("input,textarea")) { el.value = ""; el.defaultValue = ""; el.removeAttribute("value"); }
  clone.querySelector("#status").textContent = "Locked"; clone.querySelector("#count").textContent = "0 entries"; clone.querySelector("#toast").textContent = ""; clone.querySelector("#page-hash").textContent = "pending";
  download("cryptiki-v3.html", `<!doctype html>\n${clone.outerHTML}`);
}
function pageHash() { const html = document.documentElement.outerHTML.replace(/(<code id="page-hash">)[^<]*/, "$1"); sha(enc.encode(html)).then(x => $("page-hash").textContent = hex(x)); }
window.addEventListener("DOMContentLoaded", () => {
  $("version").textContent = VERSION; $("unlock").onclick = () => unlock(false); $("create").onclick = () => unlock(true); $("lock").onclick = lock; $("new-entry").onclick = newEntry; $("save").onclick = saveVault; $("export").onclick = exportVault; $("import").onclick = importVault; $("change").onclick = changeCredentials; $("save-app").onclick = saveApp; $("delete").onclick = deleteCurrentVault; $("retry-old-delete").onclick = retryOldDeletion; $("cancel-credentials").onclick = () => $("credential-dialog").close(); $("credential-form").addEventListener("submit", rotateCredentials); $("search").oninput = renderEntries; $("dismiss").onclick = () => $("notice").hidden = true; $("name").focus(); pageHash();
  $("toggle-all").onclick = () => { state.showAll = !state.showAll; renderEntries(); };
  $("clear-search").onclick = () => { $("search").value = ""; $("search").focus(); renderEntries(); };
  /* Theme follows the OS until the user overrides it; nothing is persisted. */
  const dark = matchMedia("(prefers-color-scheme: dark)"); let chosen = false;
  applyTheme(dark.matches ? "dark" : "light");
  dark.addEventListener("change", event => { if (!chosen) applyTheme(event.matches ? "dark" : "light"); });
  $("theme").onclick = () => { chosen = true; applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"); };
  document.addEventListener("keydown", touch);
  document.addEventListener("keydown", event => {
    const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName);
    if (event.key === "/" && !typing && !$("editor-screen").hidden) { event.preventDefault(); $("search").focus(); $("search").select(); }
    if (document.activeElement !== $("search")) return;
    if (event.key === "Escape" && $("search").value) { $("search").value = ""; renderEntries(); }
    if (event.key === "Enter") { const top = visibleEntries()[0]; if (top) copySecret(top.password, null, `Password for ${top.service}`); }
  });
  document.addEventListener("visibilitychange", () => { if (document.hidden) state.hiddenAt = Date.now(); else if (state.hiddenAt && Date.now() - state.hiddenAt > 60_000) lock(); else touch(); }); window.addEventListener("beforeunload", e => { if (state.dirty) { e.preventDefault(); e.returnValue = ""; } });
});
