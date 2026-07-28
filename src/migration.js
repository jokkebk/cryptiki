const API_BASE = (globalThis.MIGRATION_API || (location.protocol === "file:" ? "https://cryptiki.com" : "")).replace(/\/$/, "");
const DEBUG = new URL(location.href).searchParams.get("debug") === "1";
const state = { oldPasswordTag: null, entries: null, plaintext: "", format: 0, legacy: null, capsule: null, keys: null, lockTimer: 0, hiddenAt: 0 };
const $ = id => document.getElementById(id);
const recoveryArgon2 = (password, salt, options) => globalThis.argon2idAsync(password, salt, { ...options, onProgress: value => { $("progress").value = value; } });

function status(message, error = false) { $("status").textContent = message; $("status").className = error ? "error" : "muted"; }
function debug(message) {
  if (!DEBUG) return;
  const line = `[debug] ${message}`;
  console.info(`[Cryptiki migration] ${message}`);
  const output = $("debug-output");
  if (output) { output.hidden = false; output.textContent += `${output.textContent ? "\n" : ""}${line}`; }
}
function busy(value) { document.body.classList.toggle("busy", value); for (const id of ["recover", "clear", "create", "retry", "restart", "lock-preview", "lock-parse"]) if ($(id)) $(id).disabled = value; }
function wipe(value) {
  if (value instanceof Uint8Array) value.fill(0);
  else if (value && typeof value === "object") for (const child of Object.values(value)) wipe(child);
}
function clearSensitive() {
  clearTimeout(state.lockTimer); state.lockTimer = 0;
  wipe(state.legacy); wipe(state.capsule); wipe(state.keys); wipe(state.entries);
  wipe(state.oldPasswordTag); state.oldPasswordTag = null; state.entries = null; state.plaintext = ""; state.format = 0; state.legacy = null; state.capsule = null; state.keys = null;
  for (const id of ["old-name", "old-password", "recovery-code", "new-name", "new-password", "confirm-password"]) $(id).value = "";
  $("preview")?.replaceChildren();
}
function touch() { clearTimeout(state.lockTimer); state.lockTimer = setTimeout(lockPreview, 15 * 60 * 1000); }
function lockPreview() { clearSensitive(); show("recovery-card", true); show("preview-card", false); show("parse-failure-card", false); show("result-card", false); status("Recovered data cleared", true); busy(false); }
function sameBytes(a, b) { if (!a || !b || a.length !== b.length) return false; let result = 0; for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i]; return result === 0; }
async function passwordTag(password, salt) { return sha(cat(salt, new TextEncoder().encode(password))); }
function show(id, value) { $(id).hidden = !value; }
function genericFailure() {
  clearSensitive();
  show("recovery-card", true); show("preview-card", false); show("parse-failure-card", false); show("result-card", false); show("failure-card", true);
  status("Recovery failed", true); busy(false); $("progress").hidden = true;
}
function apiHeaders(auth) { return { Authorization: `Bearer ${b64(auth)}`, "Content-Type": "application/json" }; }

async function fetchCapsule(format, lookupId) {
  debug(`v${format}: lookup prefix ${lookupId.slice(0, 12)}…`);
  const response = await fetch(`${API_BASE}/api/legacy/recover`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ lookupId }), cache: "no-store" });
  debug(`v${format}: recovery endpoint HTTP ${response.status}`);
  if (response.status === 404) return null;
  if (!response.ok) throw Error(`recovery unavailable (HTTP ${response.status})`);
  const value = await response.json();
  if ((value.format !== 1 && value.format !== 2) || typeof value.blob !== "string") throw Error("invalid recovery response");
  const blob = unb64(value.blob, MAX_CONTENT + 64 * 1024);
  debug(`v${format}: received v${value.format} capsule (${blob.length} bytes)`);
  return { format: value.format, blob };
}

async function tryCandidate(format, name, password, recoveryCode) {
  debug(`v${format}: deriving legacy and capsule keys`);
  const material = await deriveLegacy(format, name, password, recoveryCode);
  const capsuleMaterial = await deriveCapsuleMaterial(format, material.keyhash, material.passhash, recoveryArgon2);
  const remote = await fetchCapsule(format, capsuleMaterial.lookupId);
  if (!remote) { debug(`v${format}: no capsule matched`); return null; }
  if (remote.format !== format) { debug(`v${format}: capsule format mismatch`); return null; }
  let capsule;
  try { capsule = await decryptCapsule(remote.blob, capsuleMaterial.wrapKey, format); } catch (error) { debug(`v${format}: capsule AES-GCM failed (${error?.message || "unknown error"})`); return null; }
  let plaintext;
  try { plaintext = format === 1 ? await v1Decrypt(capsule.content, password) : await v2Decrypt(capsule.content, material.passhash); } catch (error) { debug(`v${format}: legacy AES failed (${error?.message || "unknown error"})`); return null; }
  if (!await verifyPlaintext(plaintext, capsule.contentHash)) { debug(`v${format}: plaintext hash failed`); return null; }
  debug(`v${format}: plaintext hash passed; parsing entries`);
  let entries = null; let parseError = false;
  try { entries = parseLegacyEntries(plaintext, format); } catch (error) { parseError = true; debug(`v${format}: recovered plaintext could not be parsed (${error?.message || "unknown error"})`); }
  return { format, plaintext, entries, parseError, material, capsuleMaterial, capsule };
}

function renderPreview(entries) {
  const host = $("preview"); host.replaceChildren();
  if (!entries.length) { const empty = document.createElement("p"); empty.textContent = "The recovered vault has no entries."; host.append(empty); return; }
  const table = document.createElement("table");
  const head = document.createElement("thead"); const headRow = document.createElement("tr");
  for (const label of ["Service", "Username", "Password", "Note"]) { const cell = document.createElement("th"); cell.textContent = label; headRow.append(cell); }
  head.append(headRow); table.append(head);
  const body = document.createElement("tbody");
  for (const value of entries) {
    const row = document.createElement("tr");
    for (const field of ["service", "username", "password", "note"]) {
      const cell = document.createElement("td");
      if (field !== "password") cell.textContent = value[field];
      else { const input = document.createElement("input"); input.type = "password"; input.value = value[field]; input.readOnly = true; input.autocomplete = "off"; const reveal = document.createElement("button"); reveal.type = "button"; reveal.textContent = "Reveal"; reveal.addEventListener("click", () => { input.type = input.type === "password" ? "text" : "password"; reveal.textContent = input.type === "password" ? "Reveal" : "Mask"; touch(); }); cell.append(input, reveal); }
      row.append(cell);
    }
    body.append(row);
  }
  table.append(body); host.append(table);
}

async function recover(event) {
  event.preventDefault();
  const name = $("old-name").value.trim(), password = $("old-password").value, recoveryCode = $("recovery-code").value.trim();
  if (!name && !recoveryCode || !password) return status("Enter the old password and either the page name or recovery code", true);
  const selected = Number($("legacy-format").value), formats = selected ? [selected] : [1, 2];
  if ($("debug-output")) { $("debug-output").textContent = ""; $("debug-output").hidden = !DEBUG; }
  busy(true); show("failure-card", false); $("progress").hidden = false; $("progress").value = 0; status("Deriving a memory-hard recovery lookup…");
  debug(`starting formats ${formats.map(format => `v${format}`).join(", ")}`);
  try {
    let recovered = null;
    for (const format of formats) {
      try { recovered = await tryCandidate(format, name, password, recoveryCode); } catch (error) { debug(`v${format}: candidate failed (${error?.message || "unknown error"})`); recovered = null; }
      if (recovered) break;
    }
    if (!recovered) throw Error("recovery failed");
    const tagSalt = crypto.getRandomValues(new Uint8Array(16)); state.oldPasswordTag = { salt: tagSalt, digest: await passwordTag(password, tagSalt) }; state.plaintext = recovered.plaintext; state.format = recovered.format; state.legacy = recovered.material; state.capsule = recovered.capsuleMaterial; state.entries = recovered.entries;
    $("old-password").value = ""; $("new-name").value = name; $("progress").hidden = true;
    if (recovered.parseError) { show("parse-failure-card", true); status(`Password verified and v${recovered.format} plaintext recovered, but entry parsing failed`, true); }
    else { renderPreview(state.entries); show("preview-card", true); status(`Recovered and verified locally as v${recovered.format}. Choose new credentials.`); }
    touch(); busy(false);
  } catch (error) { debug(`recovery failed (${error?.message || "unknown error"})`); genericFailure(); }
}

async function createVault(event) {
  event.preventDefault();
  const name = $("new-name").value.trim(), password = $("new-password").value, confirmation = $("confirm-password").value;
  if (!state.entries || !name || !password || password !== confirmation) return status("Enter matching new v3 credentials", true);
  if (state.oldPasswordTag && sameBytes(await passwordTag(password, state.oldPasswordTag.salt), state.oldPasswordTag.digest)) return status("Choose a new master password", true);
  busy(true); $("progress").hidden = false; $("progress").value = 0; status("Creating and verifying the new v3 vault…");
  try {
    const keys = await deriveV3(name, password, recoveryArgon2); state.keys = keys;
    const doc = { format: 1, entries: state.entries.map(value => ({ ...value })) }; const blob = await encryptV3(doc, keys.encKey);
    const made = await fetch(`${API_BASE}/api/vaults/${keys.id}`, { method: "POST", headers: { ...apiHeaders(keys.auth), "If-None-Match": "*" }, body: JSON.stringify({ blob: b64(blob) }), cache: "no-store" });
    if (made.status === 409) throw Error("That new vault already exists; choose another name or password");
    if (!made.ok) throw Error("new vault creation failed");
    const read = await fetch(`${API_BASE}/api/vaults/${keys.id}`, { method: "GET", headers: apiHeaders(keys.auth), cache: "no-store" });
    if (!read.ok) throw Error("new vault verification failed");
    const saved = await read.json(); const verified = await decryptV3(unb64(saved.blob), keys.encKey);
    if (JSON.stringify(verified) !== JSON.stringify(doc)) throw Error("new vault verification failed");
    let consumed = false;
    try { const removed = await fetch(`${API_BASE}/api/legacy/recover`, { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ lookupId: state.capsule.lookupId }), cache: "no-store" }); consumed = removed.status === 204; } catch { /* the new vault is already verified; cleanup can be retried operationally */ }
    clearSensitive(); show("recovery-card", false); show("preview-card", false); show("parse-failure-card", false); show("failure-card", false); show("result-card", true); $("cleanup-status").textContent = consumed ? "The one-time recovery capsule was consumed." : "The new vault is verified, but capsule cleanup could not be confirmed; an operator must remove the capsule."; $("progress").hidden = true; status("Migration complete"); busy(false);
  } catch (error) {
    if (error?.message?.includes("already exists")) { clearSensitive(); show("preview-card", false); show("failure-card", true); $("failure").textContent = "The new vault could not be created because those credentials already identify a vault. Start again with a different new name or password."; $("progress").hidden = true; status("Migration failed", true); busy(false); }
    else genericFailure();
  }
}

function downloadText(name, content) { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], { type: "text/plain" })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
function restart() { clearSensitive(); $("failure").textContent = "Check the page name, password, format, or recovery code and try again. The tool intentionally does not reveal which check failed."; show("result-card", false); show("failure-card", false); show("preview-card", false); show("parse-failure-card", false); show("recovery-card", true); status(""); $("old-name").focus(); }

window.addEventListener("DOMContentLoaded", () => {
  if (DEBUG) debug("debug mode enabled; lookup IDs are shown only as 12-character prefixes");
  $("recovery-form").addEventListener("submit", recover); $("create-form").addEventListener("submit", createVault); $("clear").addEventListener("click", restart); $("retry").addEventListener("click", restart); $("restart").addEventListener("click", restart); $("lock-preview").addEventListener("click", lockPreview); $("lock-parse").addEventListener("click", lockPreview); $("download-recovered").addEventListener("click", () => downloadText(`cryptiki-recovered-v${state.format}.txt`, state.plaintext)); document.addEventListener("keydown", touch); document.addEventListener("visibilitychange", () => { if (document.hidden) state.hiddenAt = Date.now(); else if (state.hiddenAt && Date.now() - state.hiddenAt > 60_000) lockPreview(); else touch(); }); $("old-name").focus();
});
