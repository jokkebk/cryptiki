# Cryptiki v3 — Security Audit

**Date:** 2026-07-28
**Commit audited:** `7033a58`
**Scope:** the v3 track (`src/worker.js`, `src/client.js`, `public/index.html`, `public/_headers`,
D1 schema, deployment config/CI), the legacy capsule design (`src/migration-core.js`,
`tools/build-legacy-capsules.mjs`, `tools/import-legacy-capsules.mjs`), and the migration
implementation (`src/migration.js`, `public/migrate.html`, `/api/legacy/recover`).
**Method:** full manual read of every source, template, tool, test, migration and config file in the
repository; targeted execution of the Worker against the project's own D1 mock to confirm suspected
behaviour; read-only header/CORS probes against the live `cryptiki.com`; verification of two
Cloudflare platform assumptions against vendor documentation. `npm test` passes (15/15) on this commit.

Findings marked **[confirmed]** were reproduced, either by executing the code or by observing the
live deployment. The reproduction transcripts are quoted inline.

---

## Summary

| # | Severity | Finding |
|---|----------|---------|
| H1 | High | Rate limiting is inert: every request shares the literal key `"unknown"` |
| H2 | High | Credential guessing against the vault API is not throttled at all |
| H3 | High | A request with no `Authorization` header crashes the Worker and leaks vault existence |
| H4 | High | Production deploys on every push to `main` with no tests and unpinned supply chain |
| M1 | Medium | The revision number is not authenticated — a hostile server can silently roll a vault back |
| M2 | Medium | Credential rotation can strand a live copy under the old password, with no way to delete it |
| M3 | Medium | Migration discards successfully recovered plaintext when entry parsing fails |
| M4 | Medium | Capsule import is non-idempotent and only verified by row count |
| M5 | Medium | Expired capsules are never deleted, only hidden at read time |
| M6 | Medium | The saved offline copy — the documented mitigation — runs with no CSP |
| M7 | Medium | HSTS and the HTTPS redirect come from Cloudflare zone settings, not from the repo |
| M8 | Medium | Nothing discourages a weak, guessable vault-name/password pair |
| M9 | Medium | Request bodies are fully buffered when `Content-Length` is absent |
| M10 | Medium | Reads and writes are unmetered; storage growth has no ceiling |
| L1–L16 | Low | See the Low-severity section |

There is no finding in this audit that hands an attacker vault plaintext outright. The high-severity
items are all *the brakes not working*: the throttles that are supposed to make online guessing
expensive do nothing, and the pipeline that is supposed to stop a broken page reaching production
does not run. Section "What holds up" at the end lists the substantial parts of the design that I
tried to break and could not.

---

## High

### H1 — Rate limiting is inert: every request shares the key `"unknown"` **[confirmed]**

`src/worker.js:89` and `src/worker.js:130` key the rate limiters on `request.cf?.connectingIp`:

```js
if (!await allowed(env.CREATE_LIMITER, request.cf?.connectingIp || "unknown")) …
if (!await allowed(env.AUTH_LIMITER, `legacy:${ip}`)) …
```

`connectingIp` is not a property of `request.cf`. The documented `IncomingRequestCfProperties`
contains `asn`, `city`, `colo`, `country`, `tlsVersion` and friends; the client IP is delivered in
the `CF-Connecting-IP` **header**, not on the `cf` object. The expression is therefore always
`undefined` and the `|| "unknown"` fallback takes over for every request on Earth.

Reproduced by instrumenting the bindings and calling the Worker:

```
rate-limit keys used: ["unknown","legacy:unknown"]
```

Two consequences, and the second is the worse one:

1. **No per-IP limiting exists.** The intended per-IP throttle on vault creation and on legacy
   recovery is not in effect.
2. **The shared bucket is a global kill switch.** Because every caller lands in the same bucket, one
   attacker sending 30 requests per minute exhausts `AUTH_LIMITER` for *every* user, and
   `/api/legacy/recover` starts returning `429 {"error":"try later"}` to legitimate people trying to
   rescue their v1/v2 data. Five requests per minute does the same to vault creation. This is a
   one-line denial of service against the migration window you have to keep open for six months.

Compounding this, the Workers rate-limiting binding is documented as **per Cloudflare location** and
"permissive, eventually consistent, and intentionally designed to not be used as an accurate
accounting system". So even after the key is fixed, the effective global limit is roughly
`limit × number of colos`, and it should not be the only control.

**Fix**

```js
const ip = request.headers.get("CF-Connecting-IP") || "unknown";
```

and key the create limiter on `ip`, the legacy limiter on `legacy:${ip}`. Since Cloudflare's own
docs warn against IP-only keys (shared NATs), consider also keying the auth limiter on the vault id
(see H2) so a single targeted vault is throttled regardless of source. Add a test that asserts the
key passed to `limit()` is derived from the header — the current suite never inspects it.

---

### H2 — Credential guessing against the vault API is not throttled at all **[confirmed]**

`src/worker.js:100-101`:

```js
const current = await findVault(env, id, auth);
if (!current) { await allowed(env.AUTH_LIMITER, id); return generic(origin, request.url); }
```

The limiter is *called* and its verdict is *discarded*. `allowed()` returns a boolean that nothing
reads, so a `{ success: false }` response has no effect on the request. Reproduced with a limiter
stub that denies everything:

```
failed auth while AUTH_LIMITER says DENY -> HTTP 404 (429 would mean throttling is enforced)
```

Combined with H1, there is currently **no rate limit of any kind on `GET`/`PUT`/`DELETE`** — not on
failed authentication, and not on successful requests either.

Why this matters more here than in a typical API: in v3 the vault id, the encryption key and the
bearer token all derive from the same Argon2id root over `(vault name, master password)`. A correct
guess does not merely authenticate — it immediately yields the decryption key. There is no second
factor, no account lockout, no backoff, and no notion of a "wrong password" event anywhere in the
system. The only cost to the attacker is one Argon2id evaluation (64 MiB, t=3) per candidate, which
a single GPU host can sustain at hundreds of guesses per second.

The `null` origin allowed by CORS (`src/worker.js:16`, verified live) widens this: any web page can
embed `<iframe sandbox="allow-scripts">`, inherit origin `null`, and run guesses from visitors'
browsers and IP addresses. No credentials are involved so this is not CSRF, but it is a ready-made
distribution mechanism for online guessing — and per H1 there is no per-IP key for it to defeat
anyway. I am not recommending you drop `null` (it is what makes the saved `file://` copy work), but
it should be documented as "effectively a wildcard" rather than treated as a restriction.

**Fix**

```js
const current = await findVault(env, id, auth);
if (!current) {
  const ok = await allowed(env.AUTH_LIMITER, `${id}:${ip}`);
  return ok ? generic(origin, request.url) : json({ error: "try later" }, 429, origin, request.url);
}
```

Consider checking the limiter *before* the D1 read so throttled requests cost nothing. If you prefer
not to distinguish 429 from 404, keep returning `generic()` on throttle but still stop doing the
lookup — the point is that the attempt must become expensive, not that the status code must differ.

---

### H3 — A request with no `Authorization` header crashes the Worker and leaks vault existence **[confirmed]**

`src/worker.js:76-81`:

```js
async function findVault(env, id, auth) {
  const row = await env.DB.prepare("SELECT … FROM vaults WHERE id = ?1").bind(id).first();
  if (!row || !sameBytes(new Uint8Array(row.auth_hash), await digest(auth))) return null;
```

`bearer()` returns `null` when the header is absent or does not match
`/^Bearer ([A-Za-z0-9_-]{43})$/`. When the row exists, the short-circuit does not fire and
`digest(null)` reaches `crypto.subtle.digest("SHA-256", null)`, which throws. `api()` has no
try/catch and neither does the top-level `fetch`, so the request becomes a Worker exception (HTTP
500 / error 1101).

Reproduced against the project's own D1 mock:

```
EXISTING vault, no Authorization header  -> THREW: TypeError: … 2nd argument is not instance of ArrayBuffer…
MISSING  vault, no Authorization header  -> HTTP 404
EXISTING vault, malformed bearer         -> THREW: TypeError: …
MISSING  vault, malformed bearer         -> HTTP 404
DELETE existing, no auth                 -> THREW: …
```

Three problems:

1. **Unauthenticated existence oracle.** `500` means the vault exists, `404` means it does not — no
   credentials required. This defeats the deliberate "everything is a generic 404" design that the
   rest of `api()` maintains carefully. Vault ids are 128-bit so they cannot be enumerated, but they
   are *not* secret: they appear in the request path `/api/vaults/<id>`, which means they sit in
   browser history, corporate TLS-inspecting proxies, and any request log. An attacker holding an id
   can confirm the target is live without knowing anything else.
2. **Uncaught exception as a service.** Two bytes of a request turn into an error path with no
   response headers, no CORS, and an entry in your error budget. Trivially scriptable.
3. It contradicts `POST`, which handles the same case correctly at `src/worker.js:91`
   (`existing && (!auth || …)` short-circuits before the digest).

**Fix** — one line at the top of `api()` after `validId`:

```js
if (!auth) return generic(origin, request.url);
```

and wrap the whole `fetch` body in a try/catch that returns a generic 404/500 with the standard
headers, so no future bug can turn into an oracle. Add a regression test: the existing suite in
`tests/worker.test.mjs` always sends an `Authorization` header, which is exactly why this survived.

---

### H4 — Production deploys on every push to `main` with no tests, and the supply chain is unpinned

`.github/workflows/deploy-production.yml` runs on every push to `main` and goes straight to
`wrangler deploy --config wrangler.production.jsonc`. It never runs `npm test`.

That test command is not cosmetic — it is `check:assembled` + `check:csp` + the vector suite. Those
two checks exist precisely to catch the failure mode where `public/index.html` no longer matches
`src/`, or where the inline `script-src`/`style-src` hashes in `public/_headers` no longer match the
page. If either drifts, the deployed page's script is **blocked by CSP** and `cryptiki.com` becomes
an inert form. For a password vault, users will read a blank app as "my data is gone". You built a
good guard and then routed around it.

Related weaknesses in the same two workflows:

- **Actions are pinned to mutable tags** (`actions/checkout@v4`, `cloudflare/wrangler-action@v3`).
  A compromised tag runs with `CLOUDFLARE_API_TOKEN` in scope. That token can replace the JavaScript
  served to every user — which is exactly the "host that serves malicious JavaScript" threat the
  README declares out of scope. CI is the most likely way that threat actually materialises, so it
  deserves the strongest control you have. Pin to full commit SHAs.
- **No lockfile and no `npm ci`.** `wranglerVersion: "4"` floats within the major (the preview
  workflow does not pin at all), and the runbook uses bare `npx wrangler`. A malicious wrangler
  release executes with the deployment token.
- **No `permissions:` block**, so `GITHUB_TOKEN` gets the repository default. Add
  `permissions: { contents: read }` to both jobs.
- No deploy-time record of what shipped. The README asks releases to report the commit SHA plus the
  SHA-256 of the served `public/index.html`; nothing in CI emits either.

**Fix**

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@<full-sha>
  - uses: actions/setup-node@<full-sha>
    with: { node-version: 22 }
  - run: npm test
  - run: shasum -a 256 public/index.html
  - uses: cloudflare/wrangler-action@<full-sha>
    with:
      wranglerVersion: "4.x.y"   # exact
```

Also consider requiring a tag rather than any push to `main` for production, so an experiment on
`main` cannot reach `cryptiki.com`.

---

## Medium

### M1 — The revision number is not authenticated: silent rollback by a hostile server or DB writer

`src/client.js:44` and `:51` build the AEAD associated data as `"cryptiki.v3.blob\0" || 0x01` — the
format version and nothing else. The revision, the vault id and the auth hash are all outside the
authenticated envelope. `unlock()` (`src/client.js:211`) accepts whatever `rev` the server sends.

So a compromised Worker, a compromised D1, or anyone with the operator's Cloudflare token can serve
revision 7 in response to a request that should return revision 12. AES-GCM verifies happily — it is
genuine ciphertext under the user's key — and the client displays a stale vault as current, with
`status("Unlocked · revision 7")` as the only tell. This is precisely the scenario the retained ten
revisions make convenient: the attacker does not need to forge anything, only to select an older row
that is already sitting in the `revisions` table.

Practical impact: a password the user rotated after a breach silently reverts to the old value, and
the user re-uses it believing it is current.

**Fix** — bind freshness and identity into the AAD. The client knows both at encrypt time (`rev` is
`1` on create and `current.rev + 1` on save):

```js
const aad = cat(enc.encode("cryptiki.v3.blob\0"), version, enc.encode(`${id}:${rev}`));
```

This is a format change, so gate it behind a version byte bump (`version = 2`) and have `decrypt()`
accept both while v1 blobs still exist. It costs nothing at runtime and closes the only
freshness/binding gap I found in the v3 envelope.

### M2 — Credential rotation can strand a live copy under the old password, with no way to delete it

`src/client.js:255`, in the branch where deleting the old vault fails:

```js
if (!removed.ok && removed.status !== 204) { state.keys = next; state.rev = verified.rev;
  return status("Both vaults exist; retry deletion of the old vault", true); }
```

`state.keys` is overwritten with the new keys before returning, so the old vault's `auth` token is
gone from memory. The message asks the user to "retry deletion" — but there is **no delete control
anywhere in the UI**. `tools/index-template.html:169` offers Export, Import, Change credentials and
Save this app; nothing else. The `DELETE` endpoint exists and is reachable, but not from the app.

Result: a full, decryptable copy of the vault stays on the server, readable by anyone who knows the
*old* master password. If the reason for rotating was that the old password was exposed, the
rotation accomplished nothing and the user has no way to finish the job.

**Fix** — keep the old keys until deletion succeeds and offer an explicit retry; and add a "Delete
this vault" control (with a typed confirmation) to the Tools row so the state is recoverable in
general, not only in this branch.

### M3 — Migration discards successfully recovered plaintext when entry parsing fails

In `src/migration.js:47-61`, the capsule decrypt and the legacy decrypt each have their own
`try`/`catch`, but the final step does not:

```js
if (!await verifyPlaintext(plaintext, capsule.contentHash)) { … return null; }
return { format, plaintext, entries: parseLegacyEntries(plaintext, format), … };
```

`parseLegacyEntries` throws on several legitimate inputs. The one most likely to bite is
`src/migration-core.js:180`, where consecutive unmatched lines of a v1 page accumulate into one note
and every append is re-checked against `MAX_STRING` (16 KiB):

```js
current.note = checkText(current.note ? `${current.note}\n${line}` : line, "note");
```

A v1 page that is mostly free text — which is exactly what v1's line format encouraged — exceeds
16 KiB and throws, even though `MAX_CONTENT` allows 512 KiB. `>1000` entries and `>10000` lines
throw too.

When it throws, the exception is caught by the loop in `recover()` (line 90), the candidate is
discarded, the other format is tried and also fails, and the user gets `genericFailure()` →
`clearSensitive()` wipes state → **"Recovery failed. The tool intentionally does not reveal which
check failed."**

The deliberate vagueness is right for credential failures. It is wrong here: by this point
`verifyPlaintext` has already matched the stored `contentHash`, so the user has *proved* they hold
the correct credentials and their data has *already been decrypted in their browser*. Telling them
nothing — and throwing the plaintext away — during a one-shot six-month window is the most likely
route to real, permanent data loss in this whole system.

**Fix** — split the failure modes:

```js
let entries;
try { entries = parseLegacyEntries(plaintext, format); }
catch (error) { return { format, plaintext, entries: null, parseError: error, … }; }
```

and when `entries === null`, show a distinct card: "Your password was correct and your data was
recovered, but it could not be parsed into entries" plus a **Download recovered text** button. The
content hash has already been verified, so there is no oracle risk in saying so. Separately, raise
or remove the 16 KiB per-note cap on the v1 path — it is a v3-document hygiene limit being applied
to legacy free text.

### M4 — Capsule import is non-idempotent and only verified by row count

`tools/import-legacy-capsules.mjs:17-20` assembles each blob by repeated append:

```sql
INSERT INTO legacy_capsules (…, blob, …) VALUES ('<id>', <fmt>, unhex(''), …);
UPDATE legacy_capsules SET blob = unhex(hex(blob) || '<chunk>') WHERE lookup_id = '<id>';
```

Re-running a chunk file — the natural reaction to a network error partway through the `for` loop in
the runbook — appends the same chunk twice. The `INSERT` fails on the primary key, but the
`UPDATE`s do not, and the README explicitly says not to wrap them in a transaction. The result is a
silently corrupted blob: AES-GCM fails at recovery time, the user sees the generic "Recovery
failed", and nothing anywhere reports a problem.

The verification the runbook prescribes — "Compare the imported v1/v2 counts" — cannot detect this,
because the row count is correct.

I found no SQL-injection path here: `lookup_id` is checked against `/^[0-9a-f]{32}$/`, `format`
against `1|2`, timestamps against `Number.isSafeInteger`, and the hex chunk is re-derived from a
base64url-validated blob (`verifyCapsuleRecord`, `tools/build-legacy-capsules.mjs:117-125`). The
issue is integrity, not injection.

**Fix** — make the statements idempotent (`INSERT OR IGNORE` + set the blob rather than append, or
build the full hex in one `UPDATE … SET blob = unhex('…')` per row) and add a post-import check that
compares against the JSONL:

```sql
SELECT count(*), sum(length(blob)), format FROM legacy_capsules GROUP BY format;
```

Better still, a per-row `hex(sha256(blob))` comparison if you can afford the queries. Run this now,
against the live production table — the import has already happened, so a corrupted row may already
be sitting there waiting for a user who will conclude their data is unrecoverable.

### M5 — Expired capsules are never deleted, only hidden at read time

`src/worker.js:141-142` filters on `expires > ?2`, and `migrations/0002_legacy_capsules.sql` indexes
`expires`, but nothing ever deletes. After 2027-01-26 the full set of legacy ciphertext remains in
production D1 indefinitely, guarded only by the README's "remove … as a dated operational task".

The capsules are strongly encrypted (see "What holds up"), so this is not an immediate exposure —
it is unnecessary retention of the exact data you retired v1 and v2 to get rid of, dependent on a
human remembering something six months out.

**Fix** — add a Cron Trigger:

```jsonc
"triggers": { "crons": ["17 3 * * *"] }
```

```js
async scheduled(event, env) {
  await env.DB.prepare("DELETE FROM legacy_capsules WHERE expires < ?1").bind(Date.now()).run();
}
```

That way the window closes itself. Keep the dated task for dropping the table and the route.

### M6 — The saved offline copy — the documented mitigation — runs with no CSP

The README's answer to "a host that serves malicious JavaScript" is: "Save and use a reviewed local
copy when that threat matters." But the CSP lives entirely in `public/_headers`, i.e. in HTTP
response headers. A file opened from `file://` has no headers, so `cryptiki-v3.html` runs with:

- no `script-src` hash pinning,
- no `connect-src` restriction — the page may talk to any host,
- no `default-src 'none'`, no `base-uri`, no `form-action`.

The configuration you recommend as the *most* hardened is the *least* hardened one you ship. It also
still targets the live API (`src/client.js:2` sets `API = "https://cryptiki.com"` under `file:`), so
the saved copy is a fully functional client with its egress controls removed.

**Fix** — put the policy in the document as well as the header, so it travels with the file:

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…'; connect-src https://cryptiki.com; img-src data:; base-uri 'none'; form-action 'none'">
```

`frame-ancestors` is ignored in a meta policy, so keep the header too — the two are enforced as an
intersection, which is what you want. Implementation wrinkle: `tools/csp.mjs` currently rewrites
only `public/_headers`; extend `syncCspHashes` to rewrite the meta tag in the assembled page, and
extend `check:csp` to assert it. Note the meta tag does not change the inline `<script>` body, so
the existing hashes stay valid.

### M7 — HSTS and the HTTPS redirect come from Cloudflare zone settings, not from the repo **[confirmed]**

Cloudflare serves a matching static asset **before** invoking the Worker (`run_worker_first` is not
set, and its default is off). Confirmed live: `POST /` returns Workers Assets' own `405` with an
empty body, not the Worker's `404 "Not found"` from `src/worker.js:166`:

```
$ curl -X POST https://cryptiki.com/     ->  HTTP/2 405, content-length: 0
```

And the plain-HTTP redirect is the edge's, not the Worker's — it is `HTTP/1.1 301` with
`Content-Type: text/html; charset=UTF-8` and a body, whereas `src/worker.js:162` returns
`new Response(null, …)` with no content type:

```
$ curl -I http://cryptiki.com/   ->  HTTP/1.1 301, Content-Type: text/html; charset=UTF-8
```

So for `/` and `/migrate` — the two pages that matter — `src/worker.js:159-163` (HTTPS redirect),
`:176` (HSTS) and `:169` (`ASSET_VERSION` cache-busting) never execute. HSTS *is* present on the
live responses, which means it is coming from a Cloudflare dashboard setting. That setting is not in
this repository, is not documented in the README, is not asserted by any test, and does not
necessarily exist on the preview deployment.

The good news, also confirmed: `_headers` **does** apply to responses fetched through the `ASSETS`
binding, and it matches on the rewritten path — `/legacy-migration` (not a file, so the Worker runs
and rewrites to `/migrate`) came back carrying the `/migrate` CSP block. The route table in
`tools/csp.mjs:9-12` is correct.

**Fix**

- Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to the `/*` block in
  `public/_headers` so it is version-controlled and applies wherever the code is deployed.
- Add a conservative default CSP to `/*` (`default-src 'none'; frame-ancestors 'none'; base-uri
  'none'`) so a future HTML asset cannot ship without one. Today's coverage is complete —
  `/migrate.html` 307-redirects to `/migrate` and `/index.html` to `/` — but that is Cloudflare's
  `html_handling` default doing the work, not anything you control.
- Delete or clearly comment the dead paths in `src/worker.js` (`ASSET_VERSION`, the `/` →
  `/index.html` mapping, the `http:` branch). Right now they read as active protections.
- Note in the README that zone-level "Always Use HTTPS" and HSTS are required configuration.

### M8 — Nothing discourages a weak, guessable vault-name/password pair

Because `id`, `encKey` and `auth` all derive from `Argon2id(password, SHA-256("cryptiki.v3.vault-salt\0" || name))`:

- The salt is a deterministic function of the vault name, not a random per-user value. Two users who
  pick the same `(name, password)` land on the same id **and the same encryption key** — the second
  one to create gets a 409, but whoever guesses the pair of an existing vault gets immediate
  read/write access to the plaintext.
- Precomputation is therefore worthwhile against *popular vault names*: an attacker can build a
  dictionary against `name = "personal"` once and try it against every user who chose that name.

The UI does nothing to steer away from this. `tools/index-template.html:144` labels the field "Vault
name" with `autocomplete="username"`, which invites exactly the predictable values that make the
salt useless, and there is no password strength requirement, meter, or minimum length anywhere. The
README correctly notes that "Argon2id makes guesses expensive but cannot repair weak passwords" —
but the product never tells the user that, and with H1/H2 in place the guessing is not even
throttled.

**Fix** — cheap, all in the client:

- Reword the unlock screen: the vault name is a *second secret*, not a username. Say so.
- Enforce a floor (length + a simple entropy estimate) on **create** only, with a live meter. Do not
  block unlock.
- Say plainly that a weak name/password pair is remotely guessable, not merely offline-crackable.

### M9 — Request bodies are fully buffered when `Content-Length` is absent

`src/worker.js:64-68`:

```js
const length = Number(request.headers.get("Content-Length") || 0);
if (length && length > MAX_BODY || …) return null;
const text = await request.text();
if (text.length > MAX_BODY) return null;
```

The guard is skipped entirely for a chunked request (no `Content-Length` → `length === 0` → the
`length &&` short-circuits), and `request.text()` then reads the whole body into the Worker's 128 MB
heap before the size check runs. Cloudflare's own body cap (100 MB on the free plan) is the only
brake. Same pattern at `src/worker.js:131-136` for `MAX_RECOVERY_BODY`.

One request per OOM is a modest amplifier, but it is free for the attacker and there is no rate
limit in front of it (H1/H2).

**Fix** — reject the request when `Content-Length` is missing (legitimate clients here always set
it; `src/client.js:202` and `src/migration.js:109` both send a `JSON.stringify` body via `fetch`,
which sets it), or read from `request.body` with a byte counter and abort past `MAX_BODY`.

### M10 — Reads and writes are unmetered; storage growth has no ceiling

`GET`, `PUT` and `DELETE` consult no limiter even on success, and `CREATE_LIMITER` is broken (H1).
Each vault holds up to 128 KiB live plus ten retained revisions — ~1.4 MB — and an attacker can
create vaults at arbitrary ids of their choosing, because the Worker never checks that `id` is
derived from `auth`. Filling D1 or generating egress is bounded only by patience.

The README already anticipates this ("Cloudflare should also have a total-vault-count alarm or guard
before any large public rollout"), but the service is live now.

**Fix** — the H1/H2 fixes cover the create and failed-auth paths. Add a cheap per-vault write limiter
on `PUT`, and set up the vault-count alarm rather than leaving it as a pre-rollout intention. There
is currently **no observability configured at all** (`wrangler.production.jsonc` has no
`observability` block), so a sustained attack would leave no trace you would notice.

---

## Low

- **L1 — The clipboard promise is not kept.** `src/client.js:244` schedules
  `navigator.clipboard.writeText("").catch(() => {})` at 15 s. That call requires document focus and
  silently rejects if the user switched away — the common case after copying a password. The toast
  says "clipboard clears in 15 s" regardless. It also clobbers whatever the user copied in the
  meantime. Only clear if the clipboard still holds our value, and soften the claim.
- **L2 — The page hash proves nothing.** `src/client.js:268` hashes `document.documentElement.outerHTML`,
  i.e. the *serialised live DOM*, not the bytes of the served file — so it can never match
  `shasum -a 256 public/index.html` (today `4cfee8d8…`), which is what the README tells you to
  publish. And it is computed by the same script a hostile host would have replaced. Either remove
  it or relabel it clearly as a build fingerprint, and publish the real file hash out of band (a
  signed git tag).
- **L3 — The browser password manager is invited in.** `autocomplete="current-password"` on
  `#master-password` (`tools/index-template.html:144`) prompts the browser to store the master
  password, next to a paragraph promising "Nothing is remembered in browser storage". Use
  `autocomplete="off"` (and `new-password` on create) or drop the claim.
- **L4 — `prompt()` for secrets.** `changeCredentials` (`src/client.js:251-252`) collects the new
  master password in a `prompt()`, which renders it in clear text in a system dialog. Use the
  existing styled password inputs.
- **L5 — Wiping is weaker than advertised.** `lock()` (`src/client.js:63`) and `clearSensitive()`
  (`src/migration.js:20`) zero `Uint8Array`s, but every plaintext value — entries, notes, the
  recovered legacy text, `keyhashHex`, `lookupId` — is a JS string and cannot be zeroed. The
  guarantee is "dropped for GC", not "erased". Worth stating accurately in the README.
- **L6 — Retained revisions are unreachable.** Ten revisions are stored and pruned but no endpoint
  or UI reads them, so users have no undo — including after `importVault` (`src/client.js:249`)
  replaces the whole document with no confirmation. The README presents revisions as a control; today
  they are only recoverable by you, via direct D1 access.
- **L7 — Vault-id squatting.** The Worker never verifies that `id` derives from `auth`, so anyone who
  learns a derived id — they travel in the URL path and land in proxy and browser logs — can
  `POST` it after a delete and permanently occupy it. The legitimate owner then gets 409 on create
  and 404 on unlock for that name/password pair, forever.
- **L8 — Timing existence oracle (secondary to H3).** `findVault` short-circuits before
  `await digest(auth)` when the row is absent, so a missing vault answers measurably faster than an
  existing one with a wrong bearer. Compute the digest unconditionally.
- **L9 — `Vary: Origin` is set only when the origin is allowed** (`src/worker.js:20`). Harmless today
  because everything is `no-store`, but it should be unconditional.
- **L10 — `--recovery-code` on the command line.** `tools/verify-legacy.py:492` takes the 64-hex
  keyhash as an argv parameter, so it lands in shell history and `ps` output. The password is
  correctly read via `getpass`; do the same here (the interactive fallback at line 512 already does).
- **L11 — Personal absolute path in the repo.** `tools/verify-legacy.py:490` defaults `--dump` to
  `/Users/joonas.pihlajamaa/koodi/cryptiki_pages_20260727.sql`, and the README repeats it. Minor
  local-layout disclosure in a public repo; make it required or relative.
- **L12 — Loose blob validation.** `bodyBlob` accepts anything over 13 bytes
  (`src/worker.js:72`) although the v3 envelope needs ≥29 (1 + 12 nonce + 16 tag), and it never
  checks `blob[0] === 1` — unlike the capsule path, which checks both (`src/worker.js:145`). Tighten
  for consistency.
- **L13 — Inconsistent document limits.** `validDocument` in `src/client.js:33-37` caps entry *count*
  but not field lengths, while `migration-core.js` enforces `MAX_STRING`. A large vault therefore
  fails server-side with `400 invalid blob`, surfaced to the user as a bare "Save failed". Check the
  encrypted size client-side before `PUT` and say what happened.
- **L14 — Missing cheap headers.** No `Cross-Origin-Opener-Policy: same-origin`, no
  `Cross-Origin-Resource-Policy: same-origin`, no `require-trusted-types-for 'script'` (free, given
  the codebase already forbids `innerHTML`), and `Permissions-Policy` covers only camera/microphone/
  geolocation.
- **L15 — Preview and production are indistinguishable.** They serve byte-identical HTML against
  different databases, with no environment banner. A bookmarked preview URL silently becomes
  someone's real vault store.
- **L16 — Blanket 302 on 404.** `src/worker.js:173` redirects every unknown path to `/`, including
  API typos. Confirmed live for `/package.json`, `/.git/config`, `/src/client.js` (nothing is
  exposed — good), but it also makes broken links and probing invisible in logs.

---

## What holds up

I went looking for the classic failures and did not find them. These are load-bearing and worth not
regressing:

- **No SQL injection path.** Every D1 call is a prepared statement with bound parameters, and
  `tests/static.test.mjs` enforces that with a regex against template-literal SQL. The capsule
  importer interpolates into SQL text, but only values already validated against
  `/^[0-9a-f]{32}$/`, `1|2`, `Number.isSafeInteger`, and a re-derived hex string.
- **No XSS sink.** No `innerHTML`, `eval`, `new Function`, or `document.write` anywhere in the shipped
  pages, asserted by test. Every value reaches the DOM through `textContent` or `.value` — including
  `renderPreview` in `src/migration.js:63-77`, which renders *decrypted legacy content*, the most
  attacker-influenced data in the system. Icons are built as nodes, never parsed from markup.
- **CORS actually rejects arbitrary origins** — verified live: `Origin: https://evil.example` gets no
  `Access-Control-Allow-Origin`, `Origin: null` does. No cookies or ambient credentials anywhere, so
  there is no CSRF surface.
- **Authentication is stored and compared correctly.** Only `SHA-256(bearer)` is persisted, so a D1
  read does not yield write access, and `sameBytes` (`src/worker.js:57-62`) is a constant-time
  comparison.
- **Compare-and-swap is enforced in the statement**, not just in the pre-read: the `UPDATE` carries
  `AND auth_hash = ?4 AND rev = ?5` and the code checks `meta.changes`, so the read-then-write gap is
  not exploitable. Creation is genuinely insert-only (`ON CONFLICT DO NOTHING`) and does not reveal
  existence to a wrong bearer.
- **The capsule design is sound.** Argon2id (64 MiB, t=3, p=1) over the legacy hash material, a salt
  domain-separated by format and keyhash, HKDF with distinct `info` strings for the lookup id and the
  wrap key, AES-GCM with the legacy format bound into the AAD, and an inner `contentHash` verified
  after legacy decryption. A dump of `legacy_capsules` yields no plaintext: recovery costs one
  Argon2id evaluation per guess, the same as v3. That is a real improvement over what v1 and v2 were
  doing, and the claim in the migration page's notice is accurate.
- **`/api/legacy/recover` adds no new exposure.** The obvious worry is that a public unauthenticated
  endpoint hands out legacy ciphertext. It does not, in any meaningful sense: the 128-bit lookup id
  is itself Argon2id-derived, so it is unguessable and self-authenticating, and the only party who
  can derive one is a party who already holds `keyhash` + `passhash` — i.e. someone with the old SQL
  dump, who already has the `content` column too. The request shape is locked down tightly
  (`Object.keys(body).length !== 1`, 1 KiB cap, strict hex regex, format and header-byte checks on
  the way out). The DoS in H1 is the real problem with this endpoint, not disclosure.
- **The build pipeline is a genuinely good control.** `assemble` → `syncCspHashes` →
  `check:assembled` + `check:csp` makes it structurally impossible to edit `src/` and silently ship a
  stale page or a broken CSP hash, and it checks for external `src=`/`href=` dependencies. Its one
  weakness is H4: CI never runs it.
- **The vendored Argon2id is pinned by behaviour, not just by hash.** `tests/crypto.test.mjs` checks
  the RFC 9106 vector *and* fixed v3 derivation vectors for root, encryption key, authorization key
  and identifier. A tampered vendor file that still reproduces those is a much harder thing to build
  than one that merely passes a file-hash check. I also grepped the vendored sources for network,
  `eval`, DOM and storage access: none.
- **`_headers` route coverage is correct and verified live**, including the non-obvious
  `/legacy-migration` → `/migrate` rewrite (see M7).
- **No third-party requests, no storage APIs, no service worker, no bundler, no minification.** All
  asserted by test, and confirmed by reading the assembled pages.

---

## Suggested order

**Before anything else** — three small diffs in `src/worker.js`, all confirmed by reproduction:

1. H3: `if (!auth) return generic(...)` plus a top-level try/catch.
2. H1: key the limiters on the `CF-Connecting-IP` header.
3. H2: honour the `AUTH_LIMITER` verdict.

**This week**

4. H4: `npm test` in the production workflow; pin actions to SHAs; add `permissions: contents: read`.
5. M4: verify the *already imported* production capsule table for truncation before a user hits it.
6. M3: stop discarding verified plaintext; add the raw-download escape hatch.

**Before the recovery window closes (2027-01-26)**

7. M5: cron-delete expired capsules.
8. M7: HSTS and a default CSP in `public/_headers`; delete the dead Worker paths.
9. M1: bind `id` and `rev` into the AEAD associated data (format version bump).
10. M2: keep old keys until deletion succeeds; add a delete-vault control.

**Worth doing**

11. M6 (meta CSP in the saved copy), M8 (password strength + "the name is a second secret"),
    M9, M10, and the Low-severity list.
