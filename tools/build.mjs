import { readFileSync } from "node:fs";

const root = new URL("..", import.meta.url);
const read = name => readFileSync(new URL(name, root), "utf8");

const stripModuleSyntax = source => source
  .replace(/^import .*;\n/gm, "").replace(/^export\s+\{[^}]+\};?\n/gm, "").replace(/^export\s+default .*;?\n/gm, "")
  .replace(/export\s+(?=(const|function|class|async function)\b)/g, "");

function through(source, marker) {
  const end = source.indexOf(marker);
  if (end < 0) throw Error(`Vendor selection marker disappeared: ${marker}`);
  return source.slice(0, end + marker.length);
}

function before(source, marker) {
  const start = source.indexOf(marker);
  if (start < 0) throw Error(`Vendor selection marker disappeared: ${marker}`);
  return source.slice(0, start).trimEnd();
}

/** The upstream files stay intact under src/vendor; the standalone app embeds only Argon2id's
 * dependency closure. BLAKE2s and its SHA-2 helpers are not reachable from BLAKE2b. */
export const argon2Bundle = () => {
  const blakeConstants = before(read("src/vendor/_blake.js"), "// Mixing function G splitted in two halfs");
  const blake2b = through(read("src/vendor/blake2.js"),
    "export const blake2b = /* @__PURE__ */ createOptHasher((opts) => new BLAKE2b(opts));");
  const vendor = [
    "/* @noble/hashes 1.8.0 Argon2id vendor; MIT; source hash recorded in README. */",
    "const crypto = globalThis.crypto;",
    read("src/vendor/utils.js"), blakeConstants, read("src/vendor/_u64.js"),
    blake2b, read("src/vendor/argon2.js")
  ].join("\n");
  return `${stripModuleSyntax(vendor)}\nglobalThis.argon2idAsync = argon2idAsync;`;
};

export const buildIndex = () => read("tools/index-template.html")
  .replace("/* __VENDOR__ */", argon2Bundle())
  .replace("/* __CLIENT__ */", read("src/client.js"));

export const buildMigrate = () => read("tools/migration-template.html")
  .replace("/* __ARGON2__ */", argon2Bundle())
  .replace("/* __CORE__ */", stripModuleSyntax(read("src/migration-core.js")))
  .replace("/* __MIGRATION_APP__ */", read("src/migration.js"));

/** Assembled pages, keyed by their filename under public/. */
export const builders = { "index.html": buildIndex, "migrate.html": buildMigrate };
