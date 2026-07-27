const API_BASE = (globalThis.MIGRATION_API || (location.protocol === "file:" ? "https://cryptiki.com" : "")).replace(/\/$/, "");
const state = { oldPassword: "", entries: null, legacy: null, capsule: null, keys: null };
const $ = id => document.getElementById(id);
const recoveryArgon2 = (password, salt, options) => globalThis.argon2idAsync(password, salt, { ...options, onProgress: value => { $("progress").value = value; } });

function status(message, error = false) { $("status").textContent = message; $("status").className = error ? "error" : "muted"; }
function busy(value) { document.body.classList.toggle("busy", value); for (const id of ["recover", "clear", "create", "retry", "restart"]) if ($(id)) $(id).disabled = value; }
function wipe(value) {
  if (value instanceof Uint8Array) value.fill(0);
  else if (value && typeof value === "object") for (const child of Object.values(value)) wipe(child);
}
function clearSensitive() {
  wipe(state.legacy); wipe(state.capsule); wipe(state.keys); wipe(state.entries);
  state.oldPassword = ""; state.entries = null; state.legacy = null; state.capsule = null; state.keys = null;
  for (const id of ["old-name", "old-password", "recovery-code", "new-name", "new-password", "confirm-password"]) $(id).value = "";
  $("preview")?.replaceChildren();
}
function show(id, value) { $(id).hidden = !value; }
function genericFailure() {
  clearSensitive();
  show("recovery-card", true); show("preview-card", false); show("result-card", false); show("failure-card", true);
  status("Recovery failed", true); busy(false); $("progress").hidden = true;
}
function apiHeaders(auth) { return { Authorization: `Bearer ${b64(auth)}`, "Content-Type": "application/json" }; }

async function fetchCapsule(lookupId) {
  const response = await fetch(`${API_BASE}/api/legacy/recover`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ lookupId }), cache: "no-store" });
  if (response.status === 404) return null;
  if (!response.ok) throw Error("recovery unavailable");
  const value = await response.json();
  if ((value.format !== 1 && value.format !== 2) || typeof value.blob !== "string") throw Error("invalid recovery response");
  return { format: value.format, blob: unb64(value.blob, MAX_CONTENT + 64 * 1024) };
}

async function tryCandidate(format, name, password, recoveryCode) {
  const material = await deriveLegacy(format, name, password, recoveryCode);
  const capsuleMaterial = await deriveCapsuleMaterial(format, material.keyhash, material.passhash, recoveryArgon2);
  const remote = await fetchCapsule(capsuleMaterial.lookupId);
  if (!remote || remote.format !== format) return null;
  let capsule;
  try { capsule = await decryptCapsule(remote.blob, capsuleMaterial.wrapKey, format); } catch { return null; }
  let plaintext;
  try { plaintext = format === 1 ? await v1Decrypt(capsule.content, password) : await v2Decrypt(capsule.content, material.passhash); } catch { return null; }
  if (!await verifyPlaintext(plaintext, capsule.contentHash)) return null;
  return { format, plaintext, entries: parseLegacyEntries(plaintext, format), material, capsuleMaterial, capsule };
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
    for (const field of ["service", "username", "password", "note"]) { const cell = document.createElement("td"); cell.textContent = value[field]; row.append(cell); }
    body.append(row);
  }
  table.append(body); host.append(table);
}

async function recover(event) {
  event.preventDefault();
  const name = $("old-name").value.trim(), password = $("old-password").value, recoveryCode = $("recovery-code").value.trim();
  if (!name && !recoveryCode || !password) return status("Enter the old password and either the page name or recovery code", true);
  const selected = Number($("legacy-format").value), formats = selected ? [selected] : [1, 2];
  busy(true); show("failure-card", false); $("progress").hidden = false; $("progress").value = 0; status("Deriving a memory-hard recovery lookup…");
  try {
    let recovered = null;
    for (const format of formats) {
      try { recovered = await tryCandidate(format, name, password, recoveryCode); } catch { recovered = null; }
      if (recovered) break;
    }
    if (!recovered) throw Error("recovery failed");
    state.oldPassword = password; state.legacy = recovered.material; state.capsule = recovered.capsuleMaterial; state.entries = recovered.entries;
    $("old-password").value = ""; $("new-name").value = name; renderPreview(state.entries);
    show("preview-card", true); $("progress").hidden = true; status(`Recovered and verified locally as v${recovered.format}. Choose new credentials.`); busy(false);
  } catch { genericFailure(); }
}

async function createVault(event) {
  event.preventDefault();
  const name = $("new-name").value.trim(), password = $("new-password").value, confirmation = $("confirm-password").value;
  if (!state.entries || !name || !password || password !== confirmation) return status("Enter matching new v3 credentials", true);
  if (password === state.oldPassword) return status("The new master password must differ from the old password", true);
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
    clearSensitive(); show("recovery-card", false); show("preview-card", false); show("failure-card", false); show("result-card", true); $("progress").hidden = true; status("Migration complete"); busy(false);
  } catch (error) {
    if (error?.message?.includes("already exists")) { clearSensitive(); show("preview-card", false); show("failure-card", true); $("failure").textContent = "The new vault could not be created because those credentials already identify a vault. Start again with a different new name or password."; $("progress").hidden = true; status("Migration failed", true); busy(false); }
    else genericFailure();
  }
}

function restart() { clearSensitive(); $("failure").textContent = "Check the page name, password, format, or recovery code and try again. The tool intentionally does not reveal which check failed."; show("result-card", false); show("failure-card", false); show("preview-card", false); show("recovery-card", true); status(""); $("old-name").focus(); }

window.addEventListener("DOMContentLoaded", () => {
  $("recovery-form").addEventListener("submit", recover); $("create-form").addEventListener("submit", createVault); $("clear").addEventListener("click", restart); $("retry").addEventListener("click", restart); $("restart").addEventListener("click", restart); $("old-name").focus();
});
