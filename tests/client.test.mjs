/* Executes src/client.js itself. The browser client had no test coverage at all, which is how two
   broken export paths and a search term leaking into the saved app were all described as fixed.
   The DOM is stubbed only as far as loading the script and calling its exported functions needs. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { argon2idAsync } from "../src/vendor/argon2.js";
import { strongCredentials as coreStrongCredentials } from "../src/migration-core.js";

const SERVED_HTML = "<html><head></head><body><main>served page</main><script>/* app */</script></body></html>";

function stubElement(id) {
  return {
    id, value: "", textContent: "", className: "", hidden: false, disabled: false, type: "text",
    style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {} },
    setAttribute() {}, removeAttribute() {}, replaceChildren() {}, append() {}, focus() {},
    select() {}, close() {}, showModal() {}, click() {}, addEventListener() {},
    querySelector: () => stubElement("child"), querySelectorAll: () => [],
    set onclick(_v) {}, get onclick() { return null; },
    set oninput(_v) {}, get oninput() { return null; }
  };
}

/* Returns the client's module namespace plus the files "downloaded" during the test. */
async function loadClient() {
  const elements = new Map();
  const document = {
    documentElement: { outerHTML: SERVED_HTML, dataset: {}, cloneNode: () => ({ outerHTML: SERVED_HTML }) },
    body: { classList: { toggle() {} } },
    getElementById: id => { if (!elements.has(id)) elements.set(id, stubElement(id)); return elements.get(id); },
    createElement: tag => stubElement(tag),
    createElementNS: () => stubElement("svg"),
    createDocumentFragment: () => stubElement("fragment"),
    addEventListener() {}, querySelector: () => stubElement("q"), activeElement: { tagName: "BODY" }, hidden: false
  };
  /* defineProperty, not Object.assign: some of these (navigator) are getter-only in Node. */
  for (const [name, value] of Object.entries({
    document,
    location: { protocol: "https:", href: "https://cryptiki.com/" },
    window: { argon2idAsync, addEventListener() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    matchMedia: () => ({ matches: false, addEventListener() {} }),
    alert: () => {}, confirm: () => true, prompt: () => null
  })) Object.defineProperty(globalThis, name, { value, writable: true, configurable: true });
  /* Capture download() payloads: URL.createObjectURL is where the bytes pass through. */
  const objectUrls = new Map();
  globalThis.URL.createObjectURL = blob => { const key = `blob:${objectUrls.size}`; objectUrls.set(key, blob); return key; };
  globalThis.URL.revokeObjectURL = () => {};
  const source = readFileSync(new URL("../src/client.js", import.meta.url), "utf8");
  const exposed = "\nexport { exportVault, importVault, saveApp, encrypt, decrypt, validDocument, unb64, b64, strongCredentials, state, hkdf, derive, PRISTINE_HTML, download, wrapQuickKeys, unwrapQuickRecord, keySet };\n";
  const module = await import(`data:text/javascript;base64,${Buffer.from(source + exposed).toString("base64")}`);
  /* download() routes its bytes through URL.createObjectURL, so objectUrls holds every saved file. */
  return { module, objectUrls, elements };
}

async function readDownload(objectUrls, key) { return new Response(objectUrls.get(key)).text(); }

test("credential policy is identical in the vault client and the migration core", async () => {
  const { module } = await loadClient();
  const cases = [["", ""], ["abc", "0123456789012345678901"], ["abcd", "short"], ["abcd", "123456789012"],
    ["abcd", "1234567890123456789012"], ["vaultname", "correct horse battery"], ["a".repeat(40), "b".repeat(12)]];
  for (const [name, password] of cases) {
    assert.equal(module.strongCredentials(name, password), coreStrongCredentials(name, password),
      `policies disagree on ${JSON.stringify([name, password])}`);
  }
  assert.equal(module.strongCredentials("abcd", "123456789012"), false, "12-char password with a 4-char name is under the combined floor");
  assert.equal(module.strongCredentials("vault", "correct horse battery"), true);
});

test("base64 input is rejected on syntax and size before it is decoded", async () => {
  const { module } = await loadClient();
  for (const bad of ["", "not base64!", "====", "A".repeat(5)]) assert.throws(() => module.unb64(bad), /Invalid encoded data|too large/);
  const oversized = "A".repeat(Math.ceil((128 * 1024 + 64) / 3) * 4);
  assert.throws(() => module.unb64(oversized), /too large/);
  assert.equal(module.unb64(module.b64(Uint8Array.of(1, 2, 3))).length, 3);
  assert.throws(() => module.unb64(module.b64(new Uint8Array(200)), 100), /too large/);
});

test("the encrypted export round trips through the import path", async () => {
  const { module, objectUrls } = await loadClient();
  const key = crypto.getRandomValues(new Uint8Array(32));
  module.state.keys = { root: key, encKey: key };
  module.state.doc = { format: 1, entries: [{ id: "a", service: "mail", username: "u", password: "p", note: "n" }] };

  /* The regression: bound directly to a click, exportVault received the Event as its document. */
  await module.exportVault();
  assert.equal(objectUrls.size, 1, "export produced no file");
  const envelope = JSON.parse(await readDownload(objectUrls, [...objectUrls.keys()][0]));
  assert.equal(envelope.format, 1);
  const salt = module.unb64(envelope.salt);
  assert.equal(salt.length, 16);
  const exportKey = await module.hkdf(module.state.keys.root, salt, new TextEncoder().encode("cryptiki.v3.export"));
  assert.deepEqual(await module.decrypt(module.unb64(envelope.blob), exportKey), module.state.doc);
});

test("quick unlock wraps the vault name and root key with PRF-derived encryption", async () => {
  const { module } = await loadClient();
  const root = crypto.getRandomValues(new Uint8Array(32));
  const credentialId = crypto.getRandomValues(new Uint8Array(64));
  const prfInput = crypto.getRandomValues(new Uint8Array(32));
  const prf = crypto.getRandomValues(new Uint8Array(32));
  const record = await module.wrapQuickKeys({ name: "secret-vault-name", root }, credentialId, prfInput, prf);
  assert.equal(record.format, 1);
  assert.equal(JSON.stringify(record).includes("secret-vault-name"), false, "the vault name leaked outside the wrapper");
  const saved = await module.unwrapQuickRecord(record, prf);
  assert.equal(saved.name, "secret-vault-name");
  assert.deepEqual(saved.root, root);
  const tampered = { ...record, wrapped: (record.wrapped.startsWith("A") ? "B" : "A") + record.wrapped.slice(1) };
  await assert.rejects(module.unwrapQuickRecord(tampered, prf));
});

test("a click Event or ciphertext is never accepted as the exported document", async () => {
  const { module, objectUrls } = await loadClient();
  const key = crypto.getRandomValues(new Uint8Array(32));
  module.state.keys = { root: key, encKey: key };
  module.state.doc = { format: 1, entries: [] };
  const ciphertext = await module.encrypt(module.state.doc, key);
  for (const wrong of [{ type: "click", isTrusted: true }, ciphertext]) {
    objectUrls.clear();
    await module.exportVault(wrong, "wrong.json");
    assert.equal(objectUrls.size, 0, "a non-document was encrypted and written to disk");
  }
  /* The conflict path must hand over the document, so its export decrypts like any other. */
  objectUrls.clear();
  await module.exportVault(JSON.parse(JSON.stringify(module.state.doc)), "cryptiki-v3-conflict.json");
  assert.equal(objectUrls.size, 1);
});

test("the saved offline app carries no rendered vault data", async () => {
  const { module, objectUrls } = await loadClient();
  const secrets = ["hunter2-master", "acme-bank-login", "recovery-code-9931", "search-needle-xyz"];
  /* Put canaries everywhere the live DOM could hold them, then save. */
  for (const id of ["name", "master-password", "search", "status", "count", "toast", "page-hash"]) {
    const node = document.getElementById(id);
    node.value = secrets[0]; node.textContent = secrets[1];
  }
  document.getElementById("empty").querySelector = () => ({ textContent: `Nothing matches “${secrets[3]}”.` });
  module.saveApp();
  const saved = await readDownload(objectUrls, [...objectUrls.keys()][0]);
  for (const secret of secrets) assert.equal(saved.includes(secret), false, `saved app leaked ${secret}`);
  assert.match(saved, /^<!doctype html>\n/);
  assert.match(saved, /served page/, "the saved app must still be the application");
  assert.equal(saved, module.PRISTINE_HTML);
});

test("document bounds reject oversized fields and duplicate entry ids", async () => {
  const { module } = await loadClient();
  assert.throws(() => module.validDocument({ format: 1, entries: [{ id: "a", service: "x".repeat(16 * 1024 + 1), username: "", password: "", note: "" }] }), /too long/);
  assert.throws(() => module.validDocument({ format: 1, entries: [{ id: "a", service: "", username: "", password: "", note: "" }, { id: "a", service: "", username: "", password: "", note: "" }] }), /Invalid vault entry/);
  assert.throws(() => module.validDocument({ format: 2, entries: [] }), /Invalid vault document/);
  assert.throws(() => module.validDocument({ format: 1, entries: new Array(1001).fill({ id: "a", service: "", username: "", password: "", note: "" }) }), /Invalid vault document/);
});
