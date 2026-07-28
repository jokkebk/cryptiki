# Review of `SecurityRemediationChecklist.md`

**Date:** 2026-07-28
**Reviewed against:** `0d42a45` (= `origin/main`), plus live probes of `cryptiki.com`
**Reviewer:** the author of `SecurityAuditOpus.md`

## Verdict

The remediation is substantially real. I re-derived each code-fixed claim against the source rather
than taking the checklist at its word, and the large majority hold up — including all three of my
high-severity Worker findings, which are properly fixed and now have targeted regression tests. The
test suite grew from 15 to 22 tests and the new ones test the right things.

Four items still need work before I would call this closed, and one of them is a capability the
remediation *introduced*. There is also a process finding: the front page of `cryptiki.com` was
hard-down for roughly five minutes this morning behind two consecutive green CI runs, and nothing in
the new pipeline could have detected it.

---

## Verified as genuinely fixed

Checked in source, not just claimed:

- **H1** — `edgeKey()` reads `CF-Connecting-IP` (`src/worker.js:35-38`); test 3 asserts the key.
- **H2** — the `AUTH_LIMITER` verdict is now honoured and returns 429 (`src/worker.js:133`), and the
  check runs *before* the D1 read; test 4 covers it. A third `REQUEST_LIMITER` (120/min) was added.
- **H3** — `if (!auth) return generic(...)` at `src/worker.js:132`, `findVault` digests
  unconditionally (`:106`) which also closes the L8 timing channel, and the whole `fetch` body is
  wrapped in try/catch (`:195-220`). Test 2 covers it. I re-ran my original repro: no crash, generic
  404 for both existing and missing vaults.
- **H4** — both workflows gained a `test` job gate, `permissions: contents: read`, SHA-pinned
  actions, and an exact Wrangler version.
- **M3** — the best fix in the set. `parseLegacyEntries` failure no longer discards the plaintext
  (`src/migration.js:65-67`); a dedicated `parse-failure-card` explains that the password *was*
  correct and offers **Download recovered text**. This was the most likely route to real data loss
  and it is properly closed.
- **M5** — `scheduled()` deletes expired capsules and both configs have the cron.
- **M6** — `__CSP_META__` placeholder in both templates, synced by `tools/csp.mjs:27-28` and asserted
  by `tools/check-csp-hash.mjs:23-24`. The saved offline copy now carries `default-src 'none'` and a
  `connect-src` limited to `https://cryptiki.com`, which was the point.
- **M7** — HSTS and the other headers are in `public/_headers` (source-controlled), and
  `run_worker_first: true` makes the Worker's own logic live rather than dead. See the caveat below.
- **M8** — `strongCredentials()` (`src/client.js:77`) enforces 4+/12+/24 combined on create only, the
  field is relabelled "Vault name — a second secret", and the copy says a weak pair "can be guessed
  online". Exactly right.
- **M9** — `requestText()` streams with a running byte counter and cancels past the cap
  (`src/worker.js:69-92`); test 8 covers chunked bodies.
- **M2, L1, L3, L4, L9, L12, L13, L16** — vault deletion control added with a typed confirmation,
  rotation keeps `pending.old` for a retry, `autocomplete="off"` on the credential fields, the
  credential dialog replaced `prompt()`, `Vary: Origin` unconditional, blob validation tightened to
  `>= 29 && blob[0] === 1`, `/api/*` typos return 404 instead of redirecting.

---

## Must still change

### 1. The new unauthenticated DELETE on `/api/legacy/recover` is destructive and reachable by the presumed adversary

`src/worker.js:162,175-178` added `DELETE` so a completed migration can consume its capsule
(`src/migration.js:131`). Consuming the capsule is a good idea. The authorisation model is not.

The only credential is knowledge of the 128-bit `lookupId`, and `lookupId` is derived from
`keyhash` + `passhash` — both of which are **columns in the legacy SQL dump**. Your own migration
page names that dump as the thing at risk: "Both had an SQL injection flaw which … risked extraction
of most v1 data and all v2 data." So the party you are explicitly designing against can derive every
lookup ID for all 251 rows and issue 251 DELETEs, spread across a handful of IPs to stay under the
per-IP limits, and permanently destroy the recovery dataset.

Recovery afterwards is possible (re-import from the offline dump, or D1 Time Travel within 30 days),
but nothing signals that it happened. Affected users see the deliberately vague "Recovery failed" and
conclude their data is gone. There is no `consumed_at` column and no count alarm, so the first signal
would be a user complaint.

Note this is not the read path — `GET`/`POST` disclosure is fine, because a dump holder already has
the `content` column and gains nothing. It is specifically that a *read-only* endpoint became a
*write* endpoint gated on a value the adversary already holds.

**Fix — soft-delete, so the operation stays reversible:**

```sql
ALTER TABLE legacy_capsules ADD COLUMN consumed INTEGER NOT NULL DEFAULT 0;
```

```js
// DELETE: mark, do not destroy
await env.DB.prepare("UPDATE legacy_capsules SET consumed = ?2 WHERE lookup_id = ?1")
  .bind(lookupId, Date.now()).run();
// SELECT: add "AND consumed = 0"
// scheduled(): purge rows where consumed > 0 AND consumed < now - 7 days, alongside the expiry sweep
```

That keeps the consume-on-success benefit, makes mass deletion recoverable and auditable, and gives
you a `SELECT count(*) FROM legacy_capsules WHERE consumed > 0` number to alarm on. If you would
rather not touch the schema, the simpler option is to drop `DELETE` entirely and let the expiry cron
plus the dated table drop do the cleanup — the marginal exposure reduction from early consumption is
small next to the destructive risk.

### 2. CI is green while the site is down, and the test suite structurally cannot see it

`cryptiki.com` served an infinite `307` loop on `/` and `/index.html` from roughly 09:57 to 10:02 UTC
today. Observed directly:

```
$ curl -sI https://cryptiki.com/          ->  HTTP/2 307, location: /
$ curl -sI https://cryptiki.com/index.html ->  HTTP/2 307, location: /
$ curl -sIL --max-redirs 5 https://cryptiki.com/  ->  six consecutive 307s
```

Only `/migrate` and `/legacy-migration` were reachable. For those five minutes there was no URL at
which a user could open their vault. `gh run list` shows **all three** deploys in that window —
`merge security remediation worktree`, `fix(deploy): avoid asset redirect loop`, and
`fix(deploy): use canonical root asset path` — as `completed success`.

Cause: `run_worker_first: true` (correct, and needed for M7) made the Worker's path rewriting live
for the first time. The rewrite mapped `/` → `/index.html`, but Cloudflare's asset router with the
default `html_handling: auto-trailing-slash` redirects `/index.html` → `/`. Worker rewrites, router
redirects, browser retries, forever. `0d42a45` fixed it by mapping both to `/`, and I confirmed
production is healthy again (`200`, correct CSP and HSTS). The first attempted fix, `2d1e644`, only
removed the `?v=` query and left the loop in place.

The reason this shipped is `tests/worker.test.mjs:115`:

```js
ASSETS: { fetch: url => new Response(new URL(url.url).pathname === "/" ? "app" : null, …) }
```

The mock is a lookup table that does not model `html_handling` at all, so it cannot express the
behaviour that broke the site. The test asserting `/ -> 200` passed throughout the outage.

This matters more than the five minutes. The single largest change in the remediation was routing
100% of traffic through the Worker, and the safety net you added in H4 is blind to that whole class
of defect. Two things are needed:

1. **A faithful ASSETS mock.** Model the router: `/` → 200 index, `/index.html` → 307 `/`,
   `/migrate` → 200, `/migrate.html` → 307 `/migrate`, anything else → 404. Then assert that no
   Worker-served path returns a redirect whose `Location` re-enters the Worker on a path that
   redirects again. That single invariant catches every loop of this shape.
2. **A post-deploy smoke job**, as a `needs: deploy` step, not an operator checklist line:

   ```yaml
   smoke:
     needs: deploy
     runs-on: ubuntu-latest
     steps:
       - run: |
           code=$(curl -sS -o body.html -w '%{http_code}' --max-time 20 https://cryptiki.com/)
           [ "$code" = "200" ] || { echo "front page $code"; exit 1; }
           grep -q 'id="unlock-screen"' body.html || { echo "front page has no app"; exit 1; }
           curl -sSI https://cryptiki.com/ | grep -qi 'content-security-policy' || exit 1
   ```

The "HTTPS verification" operator action in the checklist describes exactly this probe and is still
unticked — which is the evidence that it needs to be automatic rather than remembered.

### 3. There is no per-vault rate limit, despite the claim

The checklist states for SA-02/H1/H2/M10: *"client and per-vault limits are enforced before D1
reads"*. The key is the **combination** (`src/worker.js:133`):

```js
if (!await allowed(env.AUTH_LIMITER, `${actor}:${id}`)) …
```

That is 30 attempts per minute per *(IP, vault)* pair. It caps what one client can do; it does not
cap what can be done to one vault. An attacker rotating source addresses — a single cloud IPv6 /64
is 2^64 of them — gets unbounded guesses against a known vault id, and vault ids are not secret
(they travel in the URL path). My H2 finding was specifically that a correct guess yields the
decryption key immediately, so the total-attempts-per-vault ceiling is the number that matters.

**Fix** — add a second, generous limiter keyed on the vault id alone:

```jsonc
{ "name": "VAULT_LIMITER", "namespace_id": "4004", "simple": { "limit": 100, "period": 3600 } }
```

Note the genuine trade-off: a pure per-vault limiter lets anyone who learns a vault id lock the owner
out. Keep the limit well above real usage (a person unlocks a handful of times a day), and prefer
consuming it only on *failed* authentication so successful unlocks never contribute. If you decide
the lockout risk outweighs the guessing risk, that is a defensible call — but then amend the
checklist to say "per client and vault" and record the residual, rather than claiming a control that
is not there. Not being surprised again is the whole point of the exercise.

### 4. `edgeKey()` fails open into a shared bucket

```js
function edgeKey(request) {
  const ip = request.headers.get("CF-Connecting-IP");
  return ip ? `ip:${ip}` : "edge-identity-missing";
}
```

If the header is ever absent, every such request lands in one bucket — which is precisely the H1
failure mode, reintroduced as a fallback. The checklist defers this to an operator action ("verify
the Worker receives the `CF-Connecting-IP` header … reject or alert on missing edge identity"), but
it belongs in code, where it is one line and cannot be forgotten:

```js
const actor = edgeKey(request);
if (actor === null) return json({ error: "not available" }, 400, origin, request.url);
```

Fail closed. A request arriving without edge identity is not a request you want to serve from a
password vault.

---

## Should still change

### 5. Clipboard clearing is now honest but inert

`src/client.js:269` gates the clear on reading the clipboard back:

```js
setTimeout(async () => { try { if (navigator.clipboard.readText && await navigator.clipboard.readText() === value) await navigator.clipboard.writeText(""); } catch {} }, 15000);
```

`readText()` requires the `clipboard-read` permission and transient user activation. Fired from a
15-second timer with no gesture, it rejects in Chromium, is unavailable to page script in Firefox,
and requires a gesture in Safari — so the `catch` swallows it and the clipboard is now **never**
cleared, where the previous unconditional `writeText("")` at least sometimes worked. The L1 finding
was that the UI over-promised; the wording is fixed ("best-effort clipboard clear in 15 s") but the
mechanism is dead. Either clear on the next real user interaction (`lock()`, the next click, or
`visibilitychange`), or drop the claim from the toast and say plainly that the clipboard is not
cleared.

### 6. The rollback residual is honest, but the cheap half of the fix is still worth taking

M1 was moved to residual risk (SA-10) rather than fixed; the AAD is still
`"cryptiki.v3.blob\0" || 0x01` (`src/client.js:65,72`). The residual text is *correct*: binding the
revision cannot prevent replay of a genuinely older `(blob, rev)` pair, because the client keeps no
persistent checkpoint — by design, since nothing is written to storage. I accept that reasoning.

But binding `id` and `rev` into the associated data still buys something real for a few lines: it
stops a hostile server presenting revision 7's ciphertext *as* revision 12, converting a silent
rollback into a visible revision regression the user can notice and the next `If-Match` will trip
over. Worth doing behind a version-byte bump. If it stays unfixed, tighten the residual wording — it
currently implies, without stating, that client-side rollback detection is impossible.

### 7. `scheduled()` will error on a deployment without migration 0002

```js
async scheduled(_event, env) {
  if (env.DB) await env.DB.prepare("DELETE FROM legacy_capsules WHERE expires <= ?1")…
}
```

Both configs now carry the cron, including preview. If `legacy_capsules` has not been applied to a
given database the daily job throws. Wrap it in try/catch, or guard on the table's existence.

### 8. Content-type mismatch on the API 404

`src/worker.js:205` returns the literal body `"Not found"` with the JSON header set. Cosmetic, but
every other API response is JSON — return `generic()` for consistency.

---

## Checklist claims that need amending

Two entries assert more than the code delivers. Fixing the wording matters as much as fixing the
code, because this document is what future-you will trust.

| Claim | Reality |
|---|---|
| SA-02: "client **and per-vault** limits are enforced" | Only the combined `(client, vault)` key exists. See item 3. |
| SA-09/M7: "asset routing through the Worker … assembled pages and headers are checked" | Routing through the Worker is configured, but nothing checks that it *works*; it was broken in production for five minutes with tests green. See item 2. |

The residual-risk section is otherwise well judged — SA-03 in particular (assume the legacy database
was already disclosed; require rotation) is the right conclusion and is stated plainly.

---

## Suggested order

1. Item 1 — soft-delete the capsule consume path. This is the only item where the remediation made
   something worse, and it sits on data with a deadline.
2. Item 2 — faithful ASSETS mock plus a post-deploy smoke job. Cheap, and it is the control that was
   missing this morning.
3. Item 4 — fail closed on missing edge identity. One line.
4. Item 3 — add `VAULT_LIMITER`, or amend the claim.
5. Items 5–8.

Then re-tick the checklist, and run the still-unticked operator actions — particularly the imported
capsule verification, which is now doubly important: with a DELETE endpoint live, the capsule row
count is your only detector for item 1.
