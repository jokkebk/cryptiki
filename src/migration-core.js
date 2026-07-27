const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });
const V2_SALT = "Cryptiki 2.0";
const V2_ITER = 133700;
const CAPSULE_SALT = "cryptiki.recovery.salt.v1\0";
const CAPSULE_LOOKUP = "cryptiki.recovery.lookup.v1";
const CAPSULE_ENCRYPTION = "cryptiki.recovery.encryption.v1";
const CAPSULE_AAD = "cryptiki.recovery.capsule.v1\0";
const V3_SALT = "cryptiki.v3.vault-salt\0";
const V3_ENCRYPTION = "cryptiki.v3.encryption";
const V3_AUTHORIZATION = "cryptiki.v3.authorization";
const V3_IDENTIFIER = "cryptiki.v3.identifier";
const V3_AAD = "cryptiki.v3.blob\0";
const MAX_CONTENT = 512 * 1024;
const MAX_ENTRIES = 1000;
const MAX_STRING = 16 * 1024;

const webcrypto = globalThis.crypto;

export function bytes(value) { return value instanceof Uint8Array ? value : new Uint8Array(value); }
export function cat(...parts) {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
export function hex(value) { return [...bytes(value)].map(x => x.toString(16).padStart(2, "0")).join(""); }
export function unhex(value, length) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]+$/.test(value) || value.length % 2 || (length && value.length !== length * 2)) throw Error("invalid hexadecimal value");
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function b64(value) {
  const input = bytes(value);
  let text = "";
  for (let i = 0; i < input.length; i += 0x8000) text += String.fromCharCode(...input.subarray(i, i + 0x8000));
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64(value, max = MAX_CONTENT) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(value)) throw Error("invalid base64");
  const unpadded = value.replace(/=+$/, "");
  if (!unpadded || unpadded.length % 4 === 1) throw Error("invalid base64");
  const padded = unpadded.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((unpadded.length + 3) % 4);
  const raw = atob(padded);
  const out = Uint8Array.from(raw, c => c.charCodeAt(0));
  if (out.length > max) throw Error("value too large");
  return out;
}
export async function sha(value) { return bytes(await webcrypto.subtle.digest("SHA-256", bytes(value))); }
export async function hkdf(key, salt, info, length = 32) {
  const imported = await webcrypto.subtle.importKey("raw", bytes(key), "HKDF", false, ["deriveBits"]);
  return bytes(await webcrypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: bytes(salt), info: enc.encode(info) }, imported, length * 8));
}
export async function pbkdf2(password, salt) {
  const imported = await webcrypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return bytes(await webcrypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", iterations: V2_ITER, salt: bytes(salt) }, imported, 256));
}

function stringValue(value, label) {
  if (typeof value !== "string" || value.length > MAX_STRING) throw Error(`invalid ${label}`);
  return value;
}
function validHash(value) { return typeof value === "string" && /^[0-9a-fA-F]{64}$/.test(value); }
function validHex16(value) { return typeof value === "string" && /^[0-9a-fA-F]{32}$/.test(value); }

export function parseV2Envelope(content) {
  if (typeof content !== "string" || content.length > MAX_CONTENT || !content.startsWith("{")) return null;
  let value;
  try { value = JSON.parse(content); } catch { return null; }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (value.deriv !== "PBKDF2" || value.iter !== V2_ITER || value.hash !== "SHA256" || value.salt !== V2_SALT || value.crypto !== "AES256CTR") return null;
  if (!validHex16(value.iv) || typeof value.encrypted !== "string") return null;
  try { unb64(value.encrypted, MAX_CONTENT); } catch { return null; }
  return value;
}

export function detectLegacyFormat(content) {
  if (parseV2Envelope(content)) return 2;
  if (typeof content !== "string" || content.length > MAX_CONTENT) throw Error("invalid legacy content");
  try { if (unb64(content, MAX_CONTENT).length < 8) throw Error("short v1 content"); } catch { throw Error("invalid legacy content"); }
  return 1;
}

export async function deriveLegacy(format, name, password, recoveryKeyhash = "") {
  const keyhash = recoveryKeyhash ? unhex(recoveryKeyhash, 32) : format === 1
    ? await sha(enc.encode(stringValue(name, "page name")))
    : await pbkdf2(stringValue(name, "page name"), enc.encode(V2_SALT));
  const passhash = format === 1 ? await sha(enc.encode(stringValue(password, "password"))) : await pbkdf2(stringValue(password, "password"), keyhash);
  return { format, keyhash, passhash, keyhashHex: hex(keyhash) };
}

export async function deriveCapsuleMaterial(format, keyhash, passhash, argon2) {
  if (format !== 1 && format !== 2 || bytes(keyhash).length !== 32 || bytes(passhash).length !== 32) throw Error("invalid capsule material");
  const salt = await sha(cat(enc.encode(CAPSULE_SALT), Uint8Array.of(format), bytes(keyhash)));
  const root = await argon2(bytes(passhash), salt, { m: 65536, t: 3, p: 1, dkLen: 32, maxmem: 70 * 1024 * 1024 });
  const lookup = await hkdf(root, salt, CAPSULE_LOOKUP, 16);
  const wrapKey = await hkdf(root, salt, CAPSULE_ENCRYPTION, 32);
  return { salt, root, lookup, lookupId: hex(lookup), wrapKey };
}

export async function buildCapsule(row, created, expires, argon2, random = n => webcrypto.getRandomValues(new Uint8Array(n))) {
  const format = detectLegacyFormat(row.content);
  const keyhash = unhex(row.keyhash, 32), passhash = unhex(row.passhash, 32);
  if (!validHash(row.contenthash)) throw Error("invalid content hash");
  const material = await deriveCapsuleMaterial(format, keyhash, passhash, argon2);
  const payload = enc.encode(JSON.stringify({ capsuleFormat: 1, legacyFormat: format, content: row.content, contentHash: row.contenthash }));
  const nonce = bytes(random(12));
  if (nonce.length !== 12) throw Error("invalid nonce");
  const aes = await webcrypto.subtle.importKey("raw", material.wrapKey, "AES-GCM", false, ["encrypt"]);
  const ciphertext = bytes(await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: cat(enc.encode(CAPSULE_AAD), Uint8Array.of(format)), tagLength: 128 }, aes, payload));
  return { lookup_id: material.lookupId, format, blob: cat(Uint8Array.of(1, format), nonce, ciphertext), created, expires };
}

export async function decryptCapsule(blob, wrapKey, expectedFormat) {
  const value = bytes(blob);
  if (value.length < 30 || value[0] !== 1 || (value[1] !== 1 && value[1] !== 2) || (expectedFormat && value[1] !== expectedFormat)) throw Error("invalid capsule");
  const format = value[1], aes = await webcrypto.subtle.importKey("raw", bytes(wrapKey), "AES-GCM", false, ["decrypt"]);
  const payload = bytes(await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: value.subarray(2, 14), additionalData: cat(enc.encode(CAPSULE_AAD), Uint8Array.of(format)), tagLength: 128 }, aes, value.subarray(14)));
  let result;
  try { result = JSON.parse(dec.decode(payload)); } catch { throw Error("invalid capsule"); }
  if (!result || result.capsuleFormat !== 1 || result.legacyFormat !== format || typeof result.content !== "string" || !validHash(result.contentHash)) throw Error("invalid capsule");
  return result;
}

export async function v1Decrypt(contentB64, password) {
  const ciphertext = unb64(contentB64, MAX_CONTENT);
  if (ciphertext.length < 8) throw Error("invalid v1 content");
  const pw = new Uint8Array(32); pw.set(enc.encode(stringValue(password, "password")).subarray(0, 32));
  const pwKey = await webcrypto.subtle.importKey("raw", pw, "AES-CBC", false, ["encrypt"]);
  const block = bytes(await webcrypto.subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, pwKey, pw.subarray(0, 16))).subarray(0, 16);
  const key = cat(block, block);
  const counter = new Uint8Array(16); counter.set(ciphertext.subarray(0, 8));
  const aes = await webcrypto.subtle.importKey("raw", key, "AES-CTR", false, ["decrypt"]);
  return dec.decode(await webcrypto.subtle.decrypt({ name: "AES-CTR", counter, length: 64 }, aes, ciphertext.subarray(8)));
}

export async function v2Decrypt(contentJson, passhash) {
  const meta = parseV2Envelope(contentJson);
  if (!meta) throw Error("invalid v2 content");
  const aes = await webcrypto.subtle.importKey("raw", bytes(passhash), "AES-CTR", false, ["decrypt"]);
  return dec.decode(await webcrypto.subtle.decrypt({ name: "AES-CTR", counter: unhex(meta.iv, 16), length: 128 }, aes, unb64(meta.encrypted, MAX_CONTENT)));
}

export async function verifyPlaintext(plaintext, contentHash) { return hex(await sha(enc.encode(plaintext))).toLowerCase() === contentHash.toLowerCase(); }

function checkText(value, label) { return stringValue(value, label); }
function checkPlaintext(value) {
  if (typeof value !== "string" || value.length > MAX_CONTENT) throw Error("invalid plaintext");
  return value;
}
function entry(service, username, password, note) {
  return { id: globalThis.crypto.randomUUID(), service: checkText(service, "service"), username: checkText(username, "username"), password: checkText(password, "password"), note: checkText(note, "note") };
}
export function parseLegacyEntries(plaintext, format) {
  checkPlaintext(plaintext);
  if (format === 2) {
    let values;
    try { values = JSON.parse(plaintext); } catch { throw Error("invalid v2 document"); }
    if (!Array.isArray(values) || values.length > MAX_ENTRIES) throw Error("invalid v2 document");
    return values.map(value => {
      if (!value || typeof value !== "object" || Array.isArray(value)) throw Error("invalid v2 entry");
      return entry(value.service, value.username, value.password, value.text ?? "");
    });
  }
  const lines = plaintext.split(/\r?\n/);
  if (lines.length > 10000) throw Error("v1 document too large");
  const entries = [];
  let current = null, section = "";
  for (const line of lines) {
    if (line.startsWith("!")) { section = checkText(line.slice(1).trim(), "section"); continue; }
    const match = /^([^:\n]{1,256}):\s*(.*?)\s*\/\s*(.*)$/.exec(line);
    if (match) {
      if (entries.length >= MAX_ENTRIES) throw Error("too many entries");
      current = entry(match[1].trim(), match[2], match[3], section);
      entries.push(current); continue;
    }
    if (line.trim()) {
      if (!current) current = entry("Imported note", "", "", "");
      current.note = checkText(current.note ? `${current.note}\n${line}` : line, "note");
    }
  }
  return entries;
}

export function validV3Document(doc) {
  if (!doc || doc.format !== 1 || !Array.isArray(doc.entries) || doc.entries.length > MAX_ENTRIES) throw Error("invalid v3 document");
  for (const value of doc.entries) {
    if (!value || typeof value.id !== "string" || typeof value.service !== "string" || typeof value.username !== "string" || typeof value.password !== "string" || typeof value.note !== "string") throw Error("invalid v3 entry");
    for (const [label, field] of [["service", value.service], ["username", value.username], ["password", value.password], ["note", value.note]]) checkText(field, label);
  }
  return doc;
}

export async function deriveV3(name, password, argon2, progress) {
  const vaultName = checkText(name.trim(), "vault name");
  const nameSalt = await sha(cat(enc.encode(V3_SALT), enc.encode(vaultName)));
  const root = await argon2(enc.encode(stringValue(password, "password")), nameSalt, { m: 65536, t: 3, p: 1, dkLen: 32, maxmem: 70 * 1024 * 1024, asyncTick: 20, onProgress: progress });
  const [encKey, auth, idBytes] = await Promise.all([hkdf(root, nameSalt, V3_ENCRYPTION), hkdf(root, nameSalt, V3_AUTHORIZATION), hkdf(root, nameSalt, V3_IDENTIFIER, 16)]);
  return { name: vaultName, password, nameSalt, root: bytes(root), encKey, auth, id: hex(idBytes) };
}

export async function encryptV3(doc, key) {
  validV3Document(doc);
  const compressed = bytes(await new Response(new Blob([enc.encode(JSON.stringify(doc))]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const aes = await webcrypto.subtle.importKey("raw", bytes(key), "AES-GCM", false, ["encrypt"]);
  const ciphertext = bytes(await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: cat(enc.encode(V3_AAD), Uint8Array.of(1)), tagLength: 128 }, aes, compressed));
  return cat(Uint8Array.of(1), nonce, ciphertext);
}

export async function decryptV3(blob, key) {
  const value = bytes(blob); if (value.length < 29 || value[0] !== 1) throw Error("invalid v3 blob");
  const aes = await webcrypto.subtle.importKey("raw", bytes(key), "AES-GCM", false, ["decrypt"]);
  const compressed = bytes(await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: value.subarray(1, 13), additionalData: cat(enc.encode(V3_AAD), Uint8Array.of(1)), tagLength: 128 }, aes, value.subarray(13)));
  return validV3Document(JSON.parse(await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).text()));
}

export { CAPSULE_AAD, MAX_CONTENT, MAX_ENTRIES, V2_ITER, V2_SALT };
