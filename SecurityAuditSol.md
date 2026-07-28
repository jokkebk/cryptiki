# Cryptiki v3 Security Audit

**Audit date:** 2026-07-28  
**Audited revision:** `7033a58535d303c1427410679c1050c032ed4e08` (`main`)  
**Primary focus:** v3 browser client and Worker API  
**Additional focus:** legacy capsule design, capsule build/import tooling, and the six-month migration application  
**Auditor:** OpenAI Codex

## Executive summary

Cryptiki v3 is a substantial security improvement over v1 and v2. Its core
cryptographic construction is sensible: Argon2id is used before domain-separated
HKDF outputs, encryption uses AES-256-GCM with random 96-bit nonces, the server
stores a hash of the authorization capability rather than the capability itself,
SQL statements are parameterized, and writes use compare-and-swap revisions.
The small, dependency-free browser artifact and strict CSP also make this code
unusually reviewable.

I did not find an SQL injection, DOM XSS, unauthenticated vault read/write/delete,
nonce reuse, or direct plaintext transmission in the audited code. The existing
15 tests all pass.

The audit nevertheless found four high-severity issues:

1. Credential rotation can permanently lock a user out after a single typo, and
   partial failures can leave the old credential live with no usable retry path.
2. Rate limiting is both mis-keyed and, for vault authentication failures, not
   enforced. This permits cheap D1/Worker exhaustion and lets an attacker block
   recovery traffic in a Cloudflare location.
3. Capsules protect against a *new, capsule-only* database disclosure, but cannot
   repair a prior v1/v2 database disclosure. The current migration copy overstates
   this property precisely when prior disclosure is part of the retirement threat
   model.
4. Production deploys do not run the repository's tests and execute mutable,
   major-version-tagged third-party Actions/Wrangler code. A deployment compromise
   is a full confidentiality compromise because served JavaScript sees the master
   password and plaintext.

There are also important medium-severity lifecycle and recoverability issues:
capsules are not consumed and have no committed destruction migration; the
multi-file D1 import is neither atomic nor safely resumable; recovered passwords
remain visibly rendered with no migration-page auto-lock; conflict backups are
not importable; and authenticated old ciphertext can be replayed without
detection.

**Recommended release posture:** keep v3 available only with an explicit warning
until SA-01, SA-02, and SA-04 are fixed. Keep the migration endpoint available
only if its rate limiting is fixed immediately. Treat every recovered legacy
credential as potentially compromised and require users to rotate the credentials
stored inside the recovered vault.

### Finding summary

| ID | Severity | Finding |
|---|---:|---|
| SA-01 | High | Credential rotation is non-atomic and accepts an unconfirmed new master password |
| SA-02 | High | Rate limiting is mis-keyed, bypassable, and ignored on failed vault authentication |
| SA-03 | High | Capsules do not provide retroactive protection after a legacy database disclosure |
| SA-04 | High | Production deployment runs no tests and relies on mutable supply-chain references |
| SA-05 | Medium | Capsules remain recoverable after migration and have no enforceable destruction lifecycle |
| SA-06 | Medium | Capsule import is non-atomic, non-idempotent, and insufficiently verified |
| SA-07 | Medium | Migration leaves all recovered passwords visible with no inactivity or visibility lock |
| SA-08 | Medium | “Download mine” conflict backups cannot be imported by the application |
| SA-09 | Medium | HTTPS/HSTS enforcement for static assets depends on unversioned Cloudflare settings |
| SA-10 | Medium | A storage/Worker attacker can replay an authentic older vault without detection |
| SA-11 | Low | Main-client document/import bounds are incomplete and inconsistent with migration |
| SA-12 | Low | Saved offline applications are not completely sanitized or CSP-protected |
| SA-13 | Low | Recovery-code and secret-artifact handling has avoidable local exposure paths |
| SA-14 | Informational | The security documentation understates metadata leakage and overstates replacement detection |
| SA-15 | Informational | The displayed page hash is not an authenticity mechanism |

## Scope and method

The audit covered:

- `src/client.js`
- `src/worker.js`
- `src/migration-core.js`
- `src/migration.js`
- `tools/index-template.html`
- `tools/migration-template.html`
- capsule build, import, assembly, CSP, and diagnostic tools under `tools/`
- D1 migrations under `migrations/`
- preview and production Wrangler configuration
- GitHub Actions deployment workflows
- all tests under `tests/`
- the committed assembled HTML and `_headers`
- relevant v1/v2 history needed to validate migration compatibility and assumptions

The review traced:

- credential and key derivation
- authorization and identifier construction
- AEAD formats and nonce handling
- API authentication, request validation, CORS, and rate limiting
- concurrency, deletion, revision retention, and credential rotation
- DOM rendering, secret lifetime, clipboard, import/export, and local-save behavior
- capsule derivation, legacy decryption, lookup, expiry, import, and teardown
- build/deployment integrity and CSP coverage
- accidental secret inclusion in tracked Git history

Validation performed:

- `npm test`: **15/15 passing**
- v3 and capsule cryptographic vectors: passing
- assembled-file and CSP-hash checks: passing
- focused limiter reproduction:

  ```json
  {
    "failedVaultAuthStatus": 404,
    "legacyStatus": 429,
    "limiterKeys": [
      "0123456789abcdef0123456789abcdef",
      "legacy:unknown"
    ]
  }
  ```

  The mock limiter denied both calls. Vault authentication still proceeded to a
  404 because the denial result is ignored, while a request containing
  `CF-Connecting-IP: 203.0.113.10` was nevertheless keyed as `legacy:unknown`.

- live header smoke test on 2026-07-28:
  - `http://cryptiki.com/` returned `301` to HTTPS
  - `https://cryptiki.com/` returned HSTS, the expected CSP, and `no-store`
  - `https://cryptiki.com/legacy-migration` returned HSTS, the expected CSP, and
    `no-store`

The live header result demonstrates that external Cloudflare zone settings
currently compensate for SA-09. Those external settings, GitHub branch
protection, environment approval rules, Cloudflare account security, D1 backup
retention, browser/OS compromise, and a formal cryptanalysis of the vendored
Argon2 implementation were not fully in scope.

## Threat model used

### Assets

- vault names and master passwords
- derived roots, encryption keys, and authorization capabilities
- decrypted vault contents and stored account credentials
- availability and recoverability of current and historical vault data
- legacy rows, capsules, recovery codes, and raw SQL dumps
- production deployment credentials and the integrity of served JavaScript

### Adversaries

- an unauthenticated Internet client
- an attacker with a copy of D1
- an attacker who can write D1 rows but cannot change browser code
- an attacker who previously obtained some or all of the v1/v2 database
- a compromised deployment dependency, GitHub workflow, Cloudflare token, or
  hosting account
- a malicious or compromised browser extension/local process

### Important limits

No browser-delivered zero-knowledge application can protect a password typed
into JavaScript served by a malicious host. Likewise, client-side memory wiping
in JavaScript is best effort: immutable strings, browser copies, DOM state, and
garbage-collected memory cannot be reliably zeroed.

## Detailed findings

### SA-01 — Credential rotation is non-atomic and accepts an unconfirmed new master password

**Severity:** High  
**Impact:** permanent loss of vault access; failure to revoke compromised old
credentials  
**Affected code:** `src/client.js:250-258`

The “Change vault credentials” flow asks for the new master password once using
`prompt()`. It derives the new keys from that one string, creates a second vault,
reads and decrypts that vault with the same in-memory string, and then deletes
the old vault.

The read-back proves that the program used the same key for encryption and
decryption. It does not prove that the user can reproduce what they typed. One
typo can therefore create a vault under an unknown password and immediately
delete the only copy protected by the known password. The problem is especially
serious for a password vault because the vault may contain the recovery material
for many other accounts.

The flow also has unsafe partial-failure states:

- If creation succeeds but read-back fails, the new vault remains. Retrying
  fails at insert-only creation with “already exists.”
- If deletion of the old vault fails, `state.keys` is replaced with the new
  keys, the old authorization capability exists only in a local variable that
  is then lost, and the UI has no delete-old-vault action despite telling the
  user to retry deletion.
- If rotation was meant to revoke an exposed old master password, that failure
  leaves the attacker’s credential valid.

Initial vault creation (`src/client.js:204-216`) also has no confirmation field,
although the immediate impact is smaller because a newly created vault is empty.

**Recommendation**

1. Replace both prompts with a dedicated credential-change form containing new
   name, new password, and confirmation.
2. Clear the first password value and require the user to re-enter the new
   credential for an independent derivation/read-back before deleting the old
   vault.
3. Model rotation as an explicit resumable state machine:
   `create target → verify exact document → user re-authenticates target →
   explicitly delete source`.
4. If the target already exists and can be authenticated/decrypted to the exact
   expected document, resume instead of failing.
5. Retain the old deletion capability in memory until deletion succeeds or the
   user explicitly abandons it. Provide a clear “delete old vault” retry action.
6. Offer and verify an encrypted export before destructive rotation.
7. Add failure-injection tests after every network step, plus a test showing
   that a mistyped confirmation can never delete the old vault.

### SA-02 — Rate limiting is mis-keyed, bypassable, and ignored on failed vault authentication

**Severity:** High  
**Impact:** recovery denial of service, D1 quota/cost exhaustion, Worker resource
exhaustion  
**Affected code:** `src/worker.js:31-33`, `src/worker.js:88-101`,
`src/worker.js:125-142`; both Wrangler configurations

There are three independent defects.

First, the code uses:

```js
request.cf?.connectingIp || "unknown"
```

Cloudflare does not document `connectingIp` on `request.cf`; the client address
is supplied in the `CF-Connecting-IP` request header. The current production
path therefore keys every create request as `"unknown"` and every recovery
request as `"legacy:unknown"` within a Cloudflare location.

Because Workers rate-limit counters are local to a Cloudflare location, an
attacker needs only 30 inexpensive recovery POSTs per minute from a target
location to deny recovery to all legitimate users routed there. Five create
requests similarly consume the shared create allowance.

Second, failed vault authentication calls the limiter but discards its result:

```js
if (!current) {
  await allowed(env.AUTH_LIMITER, id);
  return generic(...);
}
```

The focused reproduction confirmed that a limiter returning
`{ success: false }` still yields the ordinary 404 instead of a 429.

Third, the D1 lookup happens before the limiter call, and the key is the
attacker-controlled vault ID. Requests using fresh random 32-hex IDs therefore
force a D1 query each time and never accumulate against one key. This defeats
the limiter as a backend-protection control even if the return value is fixed.

Cloudflare documents both the `CF-Connecting-IP` pattern and the local,
eventually-consistent nature of Workers rate limiting:

- <https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/>
- <https://developers.cloudflare.com/workers/runtime-apis/request/>

**Recommendation**

1. Read the edge-provided `CF-Connecting-IP` header, not `request.cf`.
2. Apply and enforce a client/actor limit **before** any D1 query.
3. Use separate limiter bindings and namespaces for:
   - unauthenticated API traffic per client or privacy-preserving keyed client
     identifier
   - recovery attempts per client
   - operations per vault ID after the ID has passed syntax validation
   - vault creation
4. Add a coarser Cloudflare WAF/rate-limit rule in front of the Worker so random
   IDs cannot turn every request into a D1 read.
5. Do not use a shared `"unknown"` fallback in production. Treat a missing
   trusted edge identity as a deployment error or apply a deliberately
   conservative separate policy.
6. Return 429 when denied, but retain generic 404 behavior for authentication
   failures below the limit.
7. Add tests with a real limiter mock that denies calls, tests the exact key, and
   proves D1 is not called after a pre-query denial.
8. Monitor 404/429 rates, unique IDs, D1 reads, and recovery failures. Rate-limit
   bindings are not visible in the Cloudflare dashboard unless the application
   emits its own observability data.

IP-based limits can affect users behind shared NATs. That is a reason to combine
several controls, not to collapse all clients into one key.

### SA-03 — Capsules do not provide retroactive protection after a legacy database disclosure

**Severity:** High  
**Impact:** false assurance about retired-data confidentiality  
**Affected code:** `src/migration-core.js:85-112`,
`tools/migration-template.html:13`

The capsule root is derived from values already stored in the legacy row:

```text
salt = SHA-256(domain || format || keyhash)
root = Argon2id(passhash, salt)
```

This is a reasonable way to protect capsules when the attacker obtains only the
new capsule database. Such an attacker must guess the page name/password pair
and pay the Argon2id cost for each guess.

It does not protect against an attacker who previously obtained `keyhash` and
`passhash` from the legacy database:

- For v2, `passhash` was already the AES key, so the legacy row was directly
  decryptable.
- For v1, known `keyhash` and `passhash` let the attacker derive the capsule
  lookup and wrapping key without paying a password guess through Argon2id.
  The attacker can then continue attacking the legacy password/content at the
  old fast-hash security level.

The migration page currently says encapsulation makes brute forcing “as hard as
against the native v3 implementation.” That is true only for a new
capsule-database compromise. It is not true under a prior legacy-database
compromise—the exact event the retirement notice says the old SQL injection
could have caused.

There is no cryptographic way for an offline converter that lacks the raw user
password to erase this limitation.

**Recommendation**

1. Change the migration copy and README to state the exact security property:
   capsules harden the *new store* but do not remediate a past legacy-row leak.
2. Treat all legacy contents and credentials as potentially compromised.
   Continue urging users to rotate every recovered important credential; make
   that warning prominent before and after recovery.
3. Keep the recovery window as short as operationally possible and implement
   SA-05’s consumption/destruction plan.
4. Destroy or tightly quarantine raw dumps, old database replicas, logs, and
   backups according to a documented process. Record who accessed them.
5. Review old server/database logs for evidence of exploitation, while assuming
   absence of evidence is not proof of confidentiality.

### SA-04 — Production deployment runs no tests and relies on mutable supply-chain references

**Severity:** High  
**Impact:** theft of every master password and plaintext entered after a malicious
deployment  
**Affected code:** `.github/workflows/deploy-production.yml`,
`.github/workflows/deploy.yml`

Production deploys on every push to `main` but neither deployment workflow runs
`npm test`. The repository has useful assembled-artifact, CSP, crypto-vector,
API, and migration tests, yet none are a deployment gate.

The workflows also execute:

- `actions/checkout@v4`
- `cloudflare/wrangler-action@v3`
- Wrangler version `"4"` in production
- an action-selected Wrangler version in preview

These are mutable major-version references rather than immutable commit SHAs
and an exact Wrangler release. Workflow permissions are not explicitly reduced.

This project’s README correctly acknowledges that malicious served JavaScript
can steal credentials. Consequently, deployment integrity is part of the
cryptographic boundary, not ordinary CI hygiene.

**Recommendation**

1. Run `npm test` in a separate required job and make deployment depend on it.
2. Pin every GitHub Action to a reviewed full commit SHA.
3. Pin Wrangler to an exact reviewed version and record it in a lockfile or
   equivalent immutable configuration.
4. Set workflow `permissions: contents: read` and grant no additional
   `GITHUB_TOKEN` permissions unless required.
5. Give the Cloudflare token only the minimal Worker/D1 deployment permissions.
   Prefer short-lived/OIDC-style credentials if Cloudflare support permits.
6. Require protected-branch review and production-environment approval for
   changes to the browser source, Worker, CSP/build tooling, workflows, and
   vendored crypto.
7. Publish the commit SHA and SHA-256 of both deployed HTML files as a release
   artifact, then verify the live response before considering deployment
   complete.
8. Add an automated vendored-source checksum check in addition to behavioral
   vectors.
9. Explicitly disable the production `workers.dev` route unless it is required.
   Otherwise it creates an alternate hostname that may bypass zone-level WAF,
   redirect, and monitoring controls on `cryptiki.com`.

### SA-05 — Capsules remain recoverable after migration and have no enforceable destruction lifecycle

**Severity:** Medium  
**Impact:** unnecessarily long attack window; expired sensitive material remains
in primary storage and backups  
**Affected code:** `src/worker.js:125-147`,
`migrations/0002_legacy_capsules.sql`, `src/migration.js:100-120`, README

Recovery is read-only. A successful migration neither consumes nor deletes the
legacy capsule. Every capsule therefore remains available for repeated
credential guesses until its database timestamp expires, even after its owner
has safely migrated.

Expiry only gates the SELECT. There is no cleanup job, no forward migration that
drops the table, and no backup-destruction plan. Deleting
`migrations/0002_legacy_capsules.sql` after it has been applied would not remove
the production table and would make migration history less reproducible.

The `created` and `expires` values are also not authenticated inside the
capsule. A D1 writer can extend them. Such a writer could already copy the
capsule, so this is defense in depth rather than an independent confidentiality
boundary.

**Recommendation**

1. Add a one-time, separately domain-separated deletion capability whose hash is
   stored with each capsule. Do not let knowledge of the lookup ID alone delete
   a capsule, because that would turn guesses into destructive denial of service.
2. Offer deletion only after the user has verified a durable v3 vault/export,
   and make the result explicit.
3. Run a scheduled deletion of expired rows throughout the window.
4. Keep migration `0002` as immutable history. At closure, add a new forward
   migration that drops `legacy_capsules`, remove the endpoint/page, and verify
   both actions in production.
5. Define D1 Time Travel/backup retention and deletion expectations. Record the
   date at which capsules cease to exist in every recoverable copy.
6. Authenticate the intended expiry inside the capsule and make the client
   reject recovery after that date as an extra control.

### SA-06 — Capsule import is non-atomic, non-idempotent, and insufficiently verified

**Severity:** Medium  
**Impact:** some or all users can be unable to recover during the limited
migration window  
**Affected code:** `tools/import-legacy-capsules.mjs:13-40`, README import runbook

Each capsule import does the following:

1. insert a row with an empty blob
2. append one or more chunks with separate `UPDATE` statements
3. distribute those statements across independently executed SQL files

An interruption can leave an empty or truncated blob. Re-running from the
beginning fails on the primary-key INSERT. Re-running only updates can append
chunks twice. The endpoint safely rejects malformed partial capsules, so this
is not a plaintext leak, but the affected user cannot recover.

The runbook asks the operator to compare v1/v2 counts. Counts cannot detect
truncated, duplicated, reordered, or corrupted blobs.

**Recommendation**

1. Import into a staging table keyed by `(lookup_id, chunk_index)` with expected
   chunk count, total length, and SHA-256.
2. Make every chunk insertion idempotent.
3. Assemble/promote a capsule only after all chunks and the final digest match.
4. Alternatively, make the first statement an explicit reset/upsert and make
   every subsequent chunk operation offset-aware so a complete replay from the
   beginning is safe.
5. Generate a non-secret manifest containing lookup ID, format, byte length,
   and ciphertext SHA-256. Verify every production row against it, not just
   aggregate counts.
6. Test interruption and replay at every file boundary.
7. Back up the newly imported D1 database only after verification succeeds.

### SA-07 — Migration leaves all recovered passwords visible with no inactivity or visibility lock

**Severity:** Medium  
**Impact:** exposure on shared screens/devices and unnecessarily long plaintext
lifetime  
**Affected code:** `src/migration.js:3`, `src/migration.js:63-76`,
`src/migration.js:79-98`

After recovery, every stored account password is rendered as ordinary table
text. The migration page has no inactivity lock and no “lock when hidden”
behavior comparable to the v3 client. The raw old master password is also kept
as `state.oldPassword` solely to compare it with the new password.

The `wipe()` helper cannot wipe JavaScript strings, DOM copies, or garbage
collector copies. It should be treated as best effort rather than reliable
erasure.

**Recommendation**

1. Mask recovered passwords by default and provide per-row reveal/copy controls.
2. Clear all recovered DOM and state after a short inactivity period and when
   the page has been hidden beyond a short threshold.
3. Add a prominent manual lock/clear action on the preview.
4. Avoid retaining the raw old password. If exact reuse detection remains a
   requirement, retain only a short-lived comparison digest with an ephemeral
   random salt, or perform the comparison before discarding the input.
5. Explain that browser memory clearing is best effort.
6. Add UI tests that canary secrets disappear from the DOM on lock, visibility
   timeout, failure, and success.

### SA-08 — “Download mine” conflict backups cannot be imported by the application

**Severity:** Medium  
**Impact:** loss of unsaved password changes after a conflict  
**Affected code:** `src/client.js:230-249`

The conflict action writes:

```json
{ "format": 1, "blob": "..." }
```

That blob was encrypted with the main vault encryption key.

The only import path expects a normal export containing `salt`, derives a
different export key using the `cryptiki.v3.export` domain, and then attempts
decryption. A conflict file has no salt and uses the wrong key domain, so import
always fails.

A user can reasonably download “mine,” reload the server copy, and believe the
download protects the discarded changes. It does not provide an application
round trip.

**Recommendation**

1. Make “Download mine” call the same export routine/schema as normal encrypted
   export, using the in-memory conflicted document.
2. Alternatively define a separately versioned conflict format and teach import
   to decrypt it with the main key.
3. Include a human-readable format/version discriminator.
4. Add round-trip tests for normal exports, conflict exports, wrong credentials,
   malformed input, and maximum-size input.

### SA-09 — HTTPS/HSTS enforcement for static assets depends on unversioned Cloudflare settings

**Severity:** Medium  
**Impact:** future configuration drift can expose the credential-entry page to
HTTP interception  
**Affected code:** both Wrangler files, `src/worker.js:155-177`,
`public/_headers`

Cloudflare Workers Static Assets uses asset-first routing by default. Matching
HTML assets can bypass `worker.fetch()`. The Wrangler files do not set
`assets.run_worker_first`, so the Worker’s HTTP redirect and HSTS insertion do
not, by themselves, protect the actual static HTML routes.

The global `_headers` block does not declare HSTS. The direct Worker unit test
for HTTP redirect invokes `worker.fetch()` and therefore does not test the
platform’s asset-first path.

Cloudflare documents the default here:

- <https://developers.cloudflare.com/workers/static-assets/routing/worker-script/>
- <https://developers.cloudflare.com/workers/static-assets/headers/>

The live site currently returns a correct HTTP 301 and HSTS, which indicates an
external zone rule currently compensates. That rule is not represented or
tested in this repository.

**Recommendation**

1. Choose one source-controlled enforcement model:
   - set `assets.run_worker_first: true` and let the Worker redirect/add HSTS, or
   - manage Cloudflare redirect/HSTS rules as reviewed infrastructure-as-code.
2. Add HSTS to the global `_headers` block as defense in depth for HTTPS asset
   responses.
3. Add post-deployment tests against `/`, `/index.html`,
   `/legacy-migration`, `/migrate`, and API endpoints over both HTTP and HTTPS.
4. Keep the current live zone redirect until the source-controlled replacement
   is deployed and verified.

### SA-10 — A storage/Worker attacker can replay an authentic older vault without detection

**Severity:** Medium  
**Impact:** restoration of deleted entries or obsolete passwords; misleading
view of vault freshness  
**Affected code:** `src/client.js:38-53`, `src/worker.js:102-122`,
`migrations/0001_init.sql`

The vault AEAD additional data authenticates only a format domain and version.
It does not bind the vault ID or a logical revision. A D1 writer can copy one of
the retained authentic revision blobs back into `vaults`, adjust the server
revision, and the client will decrypt it as valid.

AES-GCM prevents undetected bit modification and fabrication without the key.
It does not detect replay of an old authentic ciphertext.

Robust rollback detection across a fresh stateless browser is difficult because
the server cannot be the source of the trusted monotonic value it is accused of
rolling back.

**Recommendation**

1. Document replay/rollback as an explicit residual risk.
2. Include the vault ID and logical revision in the authenticated plaintext/AAD
   for defense against accidental cross-context replacement.
3. Where practical, let users retain a trusted local/export checkpoint containing
   the highest seen revision and document hash, and warn on rollback.
4. Consider append-only externally witnessed revision commitments if rollback
   resistance becomes a requirement. Do not claim that AES-GCM alone solves it.

### SA-11 — Main-client document/import bounds are incomplete and inconsistent with migration

**Severity:** Low  
**Impact:** browser memory/CPU exhaustion and inconsistent behavior for large
vaults  
**Affected code:** `src/client.js:12`, `src/client.js:29-53`,
`src/client.js:248-249`, `src/migration-core.js:14-16`,
`src/migration-core.js:186-216`

The main client limits entry count but not individual field size, total JSON
size, import base64 size, or decompressed size. The migration implementation
limits strings to 16 KiB, while the main client does not. The server’s 128 KiB
limit applies to compressed ciphertext, so a highly compressible document can
expand far beyond that limit in the browser.

An attacker who can create a valid encrypted bomb already has the vault keys
and can delete the vault, so this is mainly self-denial and robustness rather
than a new confidentiality boundary.

**Recommendation**

1. Define one shared, versioned document validator for the main app and
   migration app.
2. Limit each field, entry IDs, total UTF-8 JSON bytes, compressed bytes, and
   decompressed bytes.
3. Reject oversized base64 before decoding and cap decompression output.
4. Add input `maxlength` as UX defense, while keeping cryptographic/parser-side
   checks authoritative.
5. Test boundary sizes, compressed bombs, malformed UTF-8, duplicate IDs, and
   extra properties.

### SA-12 — Saved offline applications are not completely sanitized or CSP-protected

**Severity:** Low  
**Impact:** small amounts of vault metadata can be written into the saved HTML;
the reviewed local artifact has weaker runtime confinement  
**Affected code:** `src/client.js:59-73`, `src/client.js:108-119`,
`src/client.js:235-247`, `src/client.js:259-268`

`saveApp()` removes the entry list and input `value` attributes. That is a good
control, but other runtime text remains:

- the empty-result message can include the current search query
- the toast can retain a service name after keyboard-copying a search result
- other future runtime attributes/text are not covered by a deny-by-default
  sanitizer

The downloaded `file:` artifact also receives no HTTP CSP header and the HTML
has no CSP meta tag. It remains self-contained, but the “reviewed local copy”
boundary is weaker than the hosted page’s strict policy.

**Recommendation**

1. Build the download from a pristine template rather than the live DOM, or
   explicitly reset every dynamic node/property before serialization.
2. Set both `.value` and `.defaultValue` on cloned form fields rather than only
   removing attributes.
3. Include an appropriate CSP meta policy for the offline artifact, with the
   same script/style hashes and only the required production API connection.
4. Add a canary test that places unique secrets in every field, search string,
   toast, note, status, and ARIA attribute and proves none appear in the saved
   bytes.

### SA-13 — Recovery-code and secret-artifact handling has avoidable local exposure paths

**Severity:** Low  
**Impact:** recovery-code or capsule exposure on multi-user/operator systems  
**Affected code:** `tools/verify-legacy.py:488-513`,
`tools/build-legacy-capsules.mjs:155-170`,
`tools/import-legacy-capsules.mjs:44-60`

The diagnostic supports `--recovery-code VALUE`. Command-line arguments can be
captured in shell history, process listings, terminal scrollback, or support
transcripts. The tool already has a safer hidden prompt.

The builders write with mode `0600` and then call `chmod`, which is good for new
files. If an operator reuses an existing output path that is currently
world-readable, truncation/write can occur before the final chmod. This is a
short local race, but these artifacts deserve conservative handling.

**Recommendation**

1. Remove the value-taking recovery-code argument or replace it with hidden
   prompt/stdin/file-descriptor input.
2. Create secret-bearing outputs with exclusive create and mode `0600`; refuse
   existing files unless the operator explicitly chooses a secure replacement
   flow.
3. Create output directories with restrictive permissions as well as files.
4. Use a private temporary directory, encrypted operator storage, and a
   documented secure-deletion/retention process.

### SA-14 — The security documentation understates metadata leakage and overstates replacement detection

**Severity:** Informational  
**Affected code:** README security boundary

D1 stores more than the three items highlighted in the introductory security
description. It also stores:

- current revision number
- creation and modification timestamps
- ciphertext length
- up to ten prior ciphertexts and their saved timestamps

The capsule table exposes legacy format and creation/expiry metadata. Traffic
and logs can expose access timing, opaque IDs, response sizes, and bearer
authorization capabilities to the hosting layer.

The README says AES-GCM detects replacement. It detects forgery, but not the
authentic rollback described in SA-10.

**Recommendation**

Document the complete metadata surface and distinguish tampering, deletion,
replay, and traffic analysis. Also document that a leaked authorization
capability permits read/write/delete but does not itself decrypt a vault.

### SA-15 — The displayed page hash is not an authenticity mechanism

**Severity:** Informational  
**Affected code:** `src/client.js:268`, footer in `tools/index-template.html`

The page calculates and displays a SHA-256 of its own live DOM after execution.
A malicious page can calculate a different value, display the expected value,
or replace the hashing code. The footer also says `commit source` rather than
embedding the audited commit.

This hash can help compare two already-trusted copies. It cannot establish that
either copy is authentic.

**Recommendation**

Publish the commit and file hashes through an independent, immutable, preferably
signed release channel. Generate the deployed footer from the release commit,
but describe it only as an identifier—not a trust anchor.

## Positive security properties

The following controls were present and worked as intended in the reviewed
code:

- Argon2id uses 64 MiB, three iterations, one lane, and a 32-byte output.
- Vault names influence the Argon2 salt, and HKDF outputs use separate domains
  for encryption, authorization, and identifier material.
- The server stores `SHA-256(auth)` rather than the bearer authorization
  capability. A read-only D1 leak cannot replay that stored hash as API auth.
- Vault encryption uses AES-256-GCM, fresh random 96-bit nonces, a 128-bit tag,
  and versioned domain-separated AAD.
- Capsule encryption also uses AES-GCM with separate derivation and AAD domains.
- The 128-bit opaque vault/capsule lookup identifiers are not realistically
  enumerable by random guessing.
- All current Worker SQL uses prepared parameters.
- Creation is insert-only and requires `If-None-Match: *`.
- Updates authenticate, use revision compare-and-swap, and retain bounded
  ciphertext history.
- The API returns a generic 404 for missing vaults and wrong authentication.
- Request content type, identifier syntax, authorization syntax, and body/blob
  sizes are checked.
- The browser code does not use `innerHTML` for vault content. Untrusted values
  are assigned with `textContent` or DOM value properties.
- Hosted pages have a strict hash-based CSP, no third-party runtime resources,
  `no-store`, `nosniff`, `no-referrer`, restricted permissions, and
  `frame-ancestors 'none'`.
- Passwords, roots, plaintext, and tokens are not intentionally written to
  localStorage, sessionStorage, or IndexedDB.
- The main client has inactivity/visibility locking and best-effort typed-array
  clearing.
- The password generator uses browser CSPRNG output. Its modulo mapping has
  small bias, but 24 characters still provide at least 144 bits of min-entropy.
- The legacy parser validates format metadata, authenticates capsules before
  parsing, verifies the historical plaintext hash, and renders migrated content
  as text rather than HTML.
- Raw SQL is parsed as data rather than executed by the conversion tool.
- Capsule JSONL/SQL output contains lookup IDs and encrypted blobs, not raw
  keyhash, passhash, content hash, or plaintext.
- Tracked Git history did not reveal a committed database password, Cloudflare
  token, private key, or populated legacy database in the patterns reviewed.

## Remediation order

### Before further promotion or publicity

1. Fix SA-01 credential creation/rotation and add destructive-flow tests.
2. Fix SA-02 and deploy a WAF-level unauthenticated request limit.
3. Gate deployment on tests and pin the supply chain per SA-04.
4. Correct the capsule security claims in SA-03.
5. Verify an encrypted export and D1 backup before changing production code.

### During the active migration window

1. Add migration auto-lock/masked preview (SA-07).
2. Make capsule imports resumable and verify every blob (SA-06).
3. Add a safe consume/delete flow and scheduled expired-row cleanup (SA-05).
4. Verify the production endpoint, capsule counts, lengths, and digests after
   every deployment.
5. Monitor rate-limit, 404, recovery-success/failure, D1-read, and Worker-error
   metrics without logging secrets or full lookup IDs.

### Before 2027-01-26

1. Prepare and test a forward migration that drops `legacy_capsules`.
2. Prepare a deployment that removes the recovery route and page.
3. Inventory D1 Time Travel, backups, generated JSONL/SQL chunks, the raw dump,
   terminal history, and operator copies.
4. Define and rehearse verifiable destruction/retention actions.
5. Notify users early enough that failed recoveries can be resolved before the
   deadline.

### After the urgent items

1. Fix the conflict export and add full import/export round-trip coverage.
2. Add shared bounded document validation and decompression limits.
3. Move HTTPS/HSTS enforcement into versioned configuration.
4. Harden and test the offline saved application.
5. Update metadata, rollback, memory-erasure, and authenticity documentation.

## Suggested regression tests

At minimum, add tests for:

- limiter denial before D1 and correct client key extraction
- random-ID request limiting
- recovery/create limits not sharing an `"unknown"` global bucket
- credential typo/confirmation mismatch preserving the old vault
- network failure after every credential-rotation step
- resuming rotation when the target already exists and decrypts correctly
- old-vault deletion retry after a partial rotation
- normal and conflict export/import round trips
- capsule import interruption and replay at every generated file boundary
- per-row imported blob length/digest verification
- migration inactivity, hidden-page, success, and failure clearing
- saved-app canary secret removal
- maximum field/document/import/decompression limits
- post-deployment HTTP redirect, HSTS, CSP, CORS, and `no-store` on every route

## Final assessment

The v3 cryptographic core is directionally strong and far better than the
retired designs. The most serious remaining risks are not an obvious primitive
failure; they are destructive client workflow, broken abuse controls, legacy
threat-model overstatement, and deployment integrity.

The capsule construction is appropriate only under this precise claim:
**a party who obtains the new capsule store, but did not obtain the old legacy
hashes, must perform the intended memory-hard guess to locate and unwrap a
capsule.** It should not be described as retroactively repairing a legacy
database disclosure.

With SA-01, SA-02, and SA-04 corrected, the migration caveat made explicit, and
the six-month data-destruction lifecycle implemented, v3 would have a much more
credible security posture. Until then, availability, recoverability, and the
integrity of the delivery pipeline remain material risks despite the sound
client-side encryption design.
