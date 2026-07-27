import test from "node:test";
import assert from "node:assert/strict";
import { argon2id, argon2idAsync } from "../src/vendor/argon2.js";

const enc = new TextEncoder();
const cat = (...xs) => { const out = new Uint8Array(xs.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of xs) { out.set(x, i); i += x.length; } return out; };
const hex = x => Buffer.from(x).toString("hex");
const sha = async x => new Uint8Array(await crypto.subtle.digest("SHA-256", x));
const hkdf = async (key, salt, info) => new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, await crypto.subtle.importKey("raw", key, "HKDF", false, ["deriveBits"]), 256));
const compress = async x => new Uint8Array(await new Response(new Blob([x]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
const decompress = async x => new Uint8Array(await new Response(new Blob([x]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer());
const encrypt = async (doc, key) => { const nonce = crypto.getRandomValues(new Uint8Array(12)); const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]); const aad = cat(enc.encode("cryptiki.v3.blob\0"), Uint8Array.of(1)); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, aes, await compress(enc.encode(JSON.stringify(doc))))); return cat(Uint8Array.of(1), nonce, ct); };
const decrypt = async (blob, key) => { const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]); const aad = cat(enc.encode("cryptiki.v3.blob\0"), Uint8Array.of(1)); const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(1, 13), additionalData: aad }, aes, blob.subarray(13)); return JSON.parse(new TextDecoder().decode(await decompress(plain))); };

test("Argon2id RFC vector and v3 derivation vector", async () => {
  assert.equal(hex(argon2id("password", "somesalt", { m: 32, t: 3, p: 4, dkLen: 32, maxmem: 1024 * 1024 })), "bb0cc80a3e671149526915418c6eefe761bb19d5d2d567a017703e0cea6ab05c");
  const salt = await sha(enc.encode("cryptiki.v3.vault-salt\0demo"));
  const root = await argon2idAsync(enc.encode("correct horse battery staple"), salt, { m: 65536, t: 3, p: 1, dkLen: 32, maxmem: 70 * 1024 * 1024 });
  assert.equal(hex(root), "adf90a7731478caff503518765d854a7724c216bac1046179346fa9657937257");
  assert.equal(hex(await hkdf(root, salt, "cryptiki.v3.encryption")), "ed6207470135c2c8b2fa51cd483d04fb7d86cb2ed4af0a045f0bdf1d801e4a7b");
  assert.equal(hex(await hkdf(root, salt, "cryptiki.v3.authorization")), "a4fcb7c2b1097c583de375665e4ec91e396425a8258891ff0291df1472267504");
  assert.equal(hex((await hkdf(root, salt, "cryptiki.v3.identifier")).subarray(0, 16)), "9467a815fb4c6be7a40cab62c936da84");
});

test("AES-GCM envelope authenticates and round-trips", async () => {
  const key = crypto.getRandomValues(new Uint8Array(32)); const doc = { format: 1, entries: [{ id: crypto.randomUUID(), service: "mail", username: "u", password: "p", note: "n" }] };
  const one = await encrypt(doc, key); const two = await encrypt(doc, key);
  assert.deepEqual(await decrypt(one, key), doc); assert.notDeepEqual(one, two);
  const wrong = crypto.getRandomValues(new Uint8Array(32));
  for (const altered of [wrong, (() => { const x = one.slice(); x[1] ^= 1; return key && x; })(), (() => { const x = one.slice(); x[20] ^= 1; return x; })(), (() => { const x = one.slice(); x[x.length - 1] ^= 1; return x; })()]) await assert.rejects(() => decrypt(altered instanceof Uint8Array && altered.length === 32 ? one : altered, altered.length === 32 ? altered : key));
});
