# Cryptiki v3

Cryptiki v3 is a small, framework-free, zero-knowledge password vault. The
browser derives all keys and encrypts the validated document before the Worker
receives it. D1 stores only an opaque identifier, a SHA-256 authorization hash,
and authenticated ciphertext. `public/index.html` is the committed deployed
file and is also the offline app downloaded by “Save this app”.

## Security boundary and limits

The server never receives the vault name, master password, plaintext,
encryption key, or a plaintext hash. No password, root, key, token, or
decrypted document is written to localStorage, sessionStorage, or IndexedDB.
Authentication is bearer authorization derived from the credentials and is
required for every read, write, and delete. Creation is insert-only; writes use
revision compare-and-swap and retain ten old ciphertext revisions.

This does not protect against a host that serves malicious JavaScript: it can
steal a password on a future visit. Save and use a reviewed local copy when
that threat matters. A database copy can guess vault-name/password pairs
offline; Argon2id makes guesses expensive but cannot repair weak passwords. A
writer with direct D1 or Worker control can delete or replace ciphertext; AES-GCM
detects replacement but cannot prevent denial of service. Exports and
infrastructure backups are the recovery controls.

The Worker rejects decoded blobs over 128 KiB and malformed identifiers and
requests. Production uses Cloudflare rate limits per IP and per vault ID;
Cloudflare should also have a total-vault-count alarm or guard before any
large public rollout. The preview deployment is deliberately separate from
`cryptiki.com`.

## Cryptographic format

The client uses the exact v3 domain separators in the implementation brief,
Argon2id with 64 MiB, three iterations, one lane, HKDF-SHA-256, deflate-raw,
and AES-256-GCM with a fresh 12-byte nonce and authenticated envelope. The
vendored Argon2id implementation is `@noble/hashes` 1.8.0, MIT licensed. The
upstream package tarball SHA-256 is
`e8a765d92c04faaccba8776411c5038cb195f812ee629fce07e1d2e6aec80ea0`; the
upstream `esm/argon2.js` SHA-256 is
`f4ef7a7d34afbdc12cb154a67e6379b4bf3c4c51c82d6599eed4d55be4d480e5`.
The fenced source is kept readable under `src/vendor/` and is inlined into the
committed HTML so a saved file has no runtime dependency.

## Development and verification

```sh
npm run assemble       # refresh the committed standalone index after source edits
npm test               # crypto vectors, failure behavior, API auth/CAS/pruning
npm run check:csp      # exact inline CSP hashes and no external HTML dependencies
```

The deployed code is intentionally unminified and has no framework, bundler,
service worker, or runtime CDN. The preview acceptance checklist also covers
keyboard-only use, a narrow viewport, credential change, saved-file API use,
and browser network inspection showing zero third-party requests.

## Deployments and releases

Create a preview-only D1 database and Worker/static-assets project, apply
`migrations/0001_init.sql`, configure the `DB` binding and Cloudflare rate
limits, then deploy with Wrangler using `wrangler.jsonc`. Never attach the
production DNS name or delete legacy data from the preview configuration.

The production configuration is `wrangler.production.jsonc`. It uses the
separate `cryptiki-v3-production` D1 database, production rate-limit namespaces,
and the `cryptiki.com` custom-domain route. Apply `migrations/0001_init.sql`
before its first deployment. The production GitHub Actions workflow runs on
pushes to `main` and deploys that configuration using the repository secrets
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` in the `production`
environment. Therefore, after those secrets and the custom domain are set up,
a push to `main` does update the Worker served at `cryptiki.com`; a push to
another branch does not. GitHub Actions deploys code only: it does not migrate
legacy data or change Namecheap nameservers.

Releases should report the git commit SHA plus the SHA-256 of the served
`public/index.html`. Keep production and preview database IDs separate.

The retirement notice intentionally links to `/legacy-migration`, an extension
point for the separate temporary migration tool. The temporary recovery path is
now implemented in `public/migrate.html` and the read-only
`/api/legacy/recover` endpoint. It has its own disposable `legacy_capsules`
table in `migrations/0002_legacy_capsules.sql`; it never reads or writes
`vaults` during recovery.

## Legacy migration runbook

The raw SQL dump is an offline secret-bearing artifact and is intentionally not
tracked. `tools/build-legacy-capsules.mjs` parses it as data, never executes
SQL, uses no network APIs, processes rows sequentially, and emits only a
600-permission JSONL capsule file plus aggregate counts and its SHA-256. It
does not decrypt legacy content or need a user's raw password:

```sh
node tools/build-legacy-capsules.mjs \
  --input "/Users/joonas.pihlajamaa/koodi/cryptiki_pages_20260727.sql" \
  --output /private/tmp/cryptiki-capsules.jsonl
node tools/import-legacy-capsules.mjs \
  --input /private/tmp/cryptiki-capsules.jsonl \
  --output-dir /private/tmp/cryptiki-capsule-chunks
for file in /private/tmp/cryptiki-capsule-chunks/chunk-*.sql; do
  npx wrangler d1 execute cryptiki-v3-production --remote \
    --file "$file" --config wrangler.production.jsonc
done
```

The importer uses binary-safe `unhex()` assembly and keeps each D1 request below
the Wrangler file-size limit; do not wrap the generated statements in an
explicit SQL transaction. The raw dump must stay offline and must never enter
Git, CI, Cloudflare, or logs. Compare the imported v1/v2 counts before asking
users to recover vaults. The temporary recovery window closes on **2027-01-26**;
remove
`public/migrate.html`, the `/api/legacy/recover` route, and migration 0002 as a
dated operational task after that window.

For a private terminal trace of one recovery attempt, use the standard-library
diagnostic tool. It reports page lookup, password-hash match, legacy AES
decryption/content-hash verification, and—when requested—the capsule lookup
and AES-GCM verification. It does not print passwords, hashes, ciphertext, or
plaintext. The `--url` mode sends only the derived opaque lookup ID to the
recovery endpoint:

```sh
python3 tools/verify-legacy.py --format 2 --url https://cryptiki.com
```

Add `--debug` to show safe stage details and the first 12 characters of the
opaque lookup ID. The browser migration page has the matching opt-in mode at
`https://cryptiki.com/legacy-migration?debug=1`; it displays candidate format,
lookup prefix, HTTP status, capsule size, and the failing stage without showing
passwords, full lookup IDs, ciphertext, or plaintext.

If the generated local JSONL capsule file is available, verify that instead:

```sh
python3 tools/verify-legacy.py --format 2 \
  --capsules /path/to/cryptiki-capsules.jsonl
```

Enter the page name exactly as it was stored in the old v2 page. If using the
old page's saved `keyhash`, provide it with `--recovery-code`; do not use the
old page's `passkey`. Keep the SQL dump, terminal history, and diagnostic
output private. A successful SQL check followed by a failed capsule check
isolates the problem to capsule derivation/import/endpoint handling; a failed
SQL check means the page name, recovery code, password, or legacy algorithm
inputs do not match the original row.
