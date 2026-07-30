# Cryptiki v3

Cryptiki v3 is a small, framework-free, zero-knowledge password vault. The
browser derives all keys and encrypts the validated document before the Worker
receives it. D1 stores an opaque identifier, a SHA-256 authorization hash,
authenticated ciphertext, revision metadata, timestamps, and ten retained
ciphertext revisions. `public/index.html` is the committed deployed file and
is also the offline app downloaded by “Save this app”.

## Security boundary and limits

The server never receives the vault name, master password, plaintext,
encryption key, or a plaintext hash. No password, root, key, token, or
decrypted document is written to localStorage, sessionStorage, or IndexedDB.
Authentication is bearer authorization derived from the credentials and is
required for every read, write, and delete. Because nothing is persisted,
closing or reloading the tab locks the vault; an open tab also auto-locks after
an hour without keyboard or pointer activity, or after fifteen minutes hidden in
the background. Those windows are usability trades — the earlier one-minute
background lock made ordinary use a string of re-unlocks — and the OS screen
lock remains the control for an unattended machine. Creation is insert-only; writes use
revision compare-and-swap and retain ten old ciphertext revisions.

This does not protect against a host that serves malicious JavaScript: it can
steal a password on a future visit. Save and use a reviewed local copy when
that threat matters. A database copy can guess vault-name/password pairs
offline; Argon2id makes guesses expensive but cannot repair weak passwords. A
writer with direct D1 or Worker control can delete or replace ciphertext; AES-GCM
detects forgery and bit modification, but not replay of an authentic older
revision and cannot prevent denial of service. Exports and infrastructure
backups are the recovery controls. JavaScript memory clearing is best effort;
browser strings, DOM copies, and garbage-collected memory cannot be reliably
zeroed.

The Worker rejects decoded blobs over 128 KiB, bounds request streams even when
`Content-Length` is absent, and applies three limits before any D1 read: per
edge identity, per identity-and-vault, and per vault. The edge identity is the
trusted `CF-Connecting-IP` header, and a request without one is refused rather
than pooled into a shared bucket, so a missing header fails closed and shows up
as a deployment error instead of silently disabling rate limiting.

The per-vault limit is what stops guessing against one vault being spread across
many source addresses. Two residual risks come with it. Cloudflare's limits are
per location and eventually consistent, so the effective global ceiling is the
configured limit multiplied by the number of data centres in play; a WAF rule is
still the operator-side control. And because the limit is keyed on the vault
alone, someone who learns a vault id can stall that vault's owner for up to a
minute. That trade is deliberate: capping distributed guessing matters more,
because a correct guess yields the decryption key outright.

`/api/legacy/recover` is read-only and accepts POST only. A lookup id is an
address derived from the retired database's own columns, so anyone holding that
database can derive every lookup id; it must never authorise a write. Capsules
are removed only by expiry and the daily Worker cron.
The preview deployment is deliberately separate from `cryptiki.com`.

## Cryptographic format

The client uses the exact v3 domain separators in the implementation brief,
Argon2id with 64 MiB, three iterations, one lane, HKDF-SHA-256, deflate-raw,
and AES-256-GCM with a fresh 12-byte nonce and authenticated envelope. The
vendored Argon2id implementation is `@noble/hashes` 1.8.0, MIT licensed. The
upstream package tarball SHA-256 is
`e8a765d92c04faaccba8776411c5038cb195f812ee629fce07e1d2e6aec80ea0`; the
upstream `esm/argon2.js` SHA-256 is
`f4ef7a7d34afbdc12cb154a67e6379b4bf3c4c51c82d6599eed4d55be4d480e5`.
The fenced source is kept readable under `src/vendor/`; the assembler inlines
Argon2id's dependency closure (BLAKE2b, not unrelated BLAKE2s/SHA-2 code) into
the committed HTML so a saved file has no runtime dependency.

## Development and verification

```sh
npm run assemble       # refresh the committed standalone index after source edits
npm run assemble:migrate # same for the temporary legacy migration page
npm test               # runs both checks below, then crypto vectors, failure behavior, API auth/CAS/pruning
npm run check:assembled # committed public/*.html still matches its template and sources
npm run check:csp      # exact inline CSP hashes and no external HTML dependencies
```

Both assemble scripts rewrite the inline CSP hashes in `public/_headers` and
embed the matching policy in each HTML file, so a saved `file:` copy retains
script, style, and connection restrictions. `check:csp` verifies both forms.

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
the daily capsule-cleanup cron, asset routing through the Worker via
`run_worker_first`, and the `cryptiki.com` custom-domain route. Apply
`migrations/0001_init.sql`
before its first deployment. The production GitHub Actions workflow runs on
pushes to `main` and deploys that configuration using the repository secrets
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` in the `production`
environment. Therefore, after those secrets and the custom domain are set up,
a push to `main` does update the Worker served at `cryptiki.com`; a push to
another branch does not. Both workflows run the full test suite before
deployment, use immutable action commits and an exact Wrangler version, and
grant the workflow token read-only contents permission. GitHub Actions deploys
code only: it does not migrate legacy data or change Namecheap nameservers.
Protected branches, production environment approval, Cloudflare token
scope/rotation, and WAF rules remain operator controls; see
`SecurityRemediationChecklist.md`.

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
  --input "/private/secure/cryptiki_pages_20260727.sql" \
  --output /private/tmp/cryptiki-capsules.jsonl
node tools/import-legacy-capsules.mjs \
  --input /private/tmp/cryptiki-capsules.jsonl \
  --output-dir /private/tmp/cryptiki-capsule-chunks \
  --manifest /private/tmp/cryptiki-capsule-manifest.json
for file in /private/tmp/cryptiki-capsule-chunks/chunk-*.sql; do
  npx --yes wrangler@4.81.0 d1 execute cryptiki-v3-production --remote \
    --file "$file" --config wrangler.production.jsonc
done
```

The importer uses binary-safe `unhex()` assembly. Each row starts with an
idempotent reset/upsert, so replaying the complete generated chunk set after an
interruption cannot append duplicate ciphertext. Do not resume from an
arbitrary middle chunk; rerun the complete set, then compare every row's
`lookup_id`, format, byte length, and SHA-256 with the private manifest before
asking users to recover vaults. The raw dump and manifest must stay offline and
must never enter Git, CI, Cloudflare, or logs. The temporary recovery window
closes on **2027-01-26**. After that window, remove `public/migrate.html` and
the `/api/legacy/recover` route, and add a new dated forward migration that
drops `legacy_capsules`. Do not edit or delete `0002_legacy_capsules.sql`:
applied migrations are immutable history, and removing one leaves already
migrated databases inconsistent with the migration table.

For a private terminal trace of one recovery attempt, use the standard-library
diagnostic tool. It reports page lookup, password-hash match, legacy AES
decryption/content-hash verification, and—when requested—the capsule lookup
and AES-GCM verification. It does not print passwords, hashes, ciphertext, or
plaintext. The `--url` mode sends only the derived opaque lookup ID to the
recovery endpoint:

```sh
python3 tools/verify-legacy.py --dump /private/secure/cryptiki_pages_20260727.sql --format 2 --url https://cryptiki.com
```

Add `--debug` to show safe stage details and the first 12 characters of the
opaque lookup ID. The browser migration page has the matching opt-in mode at
`https://cryptiki.com/legacy-migration?debug=1`; it displays candidate format,
lookup prefix, HTTP status, capsule size, and the failing stage without showing
passwords, full lookup IDs, ciphertext, or plaintext.

If the generated local JSONL capsule file is available, verify that instead:

```sh
python3 tools/verify-legacy.py --dump /private/secure/cryptiki_pages_20260727.sql --format 2 \
  --capsules /path/to/cryptiki-capsules.jsonl
```

Enter the page name exactly as it was stored in the old v2 page. If using the
old page's saved `keyhash`, enter it at the tool's hidden recovery-code prompt;
do not use the old page's `passkey`. Keep the SQL dump, terminal history, and
diagnostic output private. A successful SQL check followed by a failed capsule check
isolates the problem to capsule derivation/import/endpoint handling; a failed
SQL check means the page name, recovery code, password, or legacy algorithm
inputs do not match the original row.
