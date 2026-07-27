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
point for the separate temporary migration tool. v1/v2 migration and recovery
are out of scope here.
