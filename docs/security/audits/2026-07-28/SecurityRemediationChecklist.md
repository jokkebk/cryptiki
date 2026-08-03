# Cryptiki security remediation checklist

This document records the disposition of `SecurityAuditSol.md` and
`SecurityAuditOpus.md` for the audited 2026-07-28 revision. Code fixes are
covered by the repository test suite — including, since 2026-07-28,
`src/client.js` behaviour, which previously had none; actions marked operational require access
to Cloudflare, GitHub, D1, or private legacy artifacts and must be recorded by
the operator when completed.

## Code-fixed findings

- [x] SA-01 / M2 — creation and credential rotation require confirmation, verify
  the target document, tolerate a retry after an ambiguous create, retain the
  old deletion capability until deletion succeeds, and expose deletion controls.
- [x] SA-02 / H1 / H2 / M10 — edge IP extraction uses `CF-Connecting-IP` and a
  request without one is refused rather than pooled into a shared bucket. Three
  limits run before any D1 read: per identity, per identity-and-vault, and
  (added 2026-07-28) per vault alone, which is what stops distributed guessing
  against one target. Residual: Cloudflare limits are per location, and a leaked
  vault id can stall that vault's owner for up to a minute.
- [x] H3 — missing or malformed bearer auth returns the generic response and an
  unexpected Worker exception is contained.
- [x] SA-04 / H4 — both deploy workflows run `npm test`, publish file hashes in
  the job summary, use read-only workflow permissions, immutable action commits,
  and an exact Wrangler version.
- [x] SA-05 / M5 — expired capsules are deleted by the daily Worker cron and
  the endpoint/page remain scheduled for retirement at the window deadline. The
  caller-triggered capsule delete added in this round was removed on 2026-07-28:
  a lookup id is derivable from the retired database, so it must not authorise a
  write. Closure adds a new forward migration; `0002` is never edited.
- [x] SA-06 / M4 — capsule imports reset/upsert rows idempotently, private output
  files are exclusive and mode 0600, output directories are mode 0700, and a
  per-row length/SHA-256 manifest is generated.
- [x] SA-07 / M3 — migration passwords are masked by default, verified plaintext
  survives parser failure as a downloadable text artifact, and recovered state
  clears after inactivity, hidden-page timeout, manual lock, success, or error.
- [x] SA-08 — conflict downloads use the same encrypted export schema and round
  trip through the normal import path. Both export paths were in fact broken
  until 2026-07-28 (the button passed a click `Event`, the conflict path passed
  ciphertext, and both threw unhandled); fixed, with errors surfaced in the UI
  and `tests/client.test.mjs` covering the round trip.
- [x] SA-09 / M7 — HSTS, asset routing through the Worker, security headers, and
  embedded CSP are source-controlled; assembled pages and headers are checked.
  Routing through the Worker briefly broke the front page on 2026-07-28 (`/`
  redirect loop) with the suite green, because the ASSETS mock did not model
  Cloudflare's `html_handling`. The mock now models it, a test walks every entry
  point for cycles, and the production workflow smoke-tests the deployed site.
- [x] SA-11 / M9 / L12 / L13 — client and migration documents have field,
  document, compressed, decompressed, request-stream, and envelope bounds.
- [x] SA-12 / M6 — saved HTML is reset from dynamic values and carries an
  embedded deny-by-default CSP with the required API connection.
- [x] SA-13 / L10 / L11 — the diagnostic tool requires an explicit dump path and
  reads the recovery code only through a hidden prompt; generated artifacts use
  restrictive creation modes.
- [x] SA-14 / SA-15 / L2 / L5 — metadata, rollback, best-effort memory clearing,
  and the non-authenticating nature of the displayed build fingerprint are
  documented accurately.
- [x] M8 — new vault creation and rotation require a minimum combined credential
  length and the UI explains that the name is a second secret.
- [x] L1 / L3 / L4 / L8 / L9 / L14 / L16 — clipboard clearing is conditional
  and best effort, password-manager autofill and secret prompts are removed,
  generic auth timing is normalized, CORS variation is unconditional, cheap
  browser security headers are present, and API typos no longer redirect.

## Required operator actions

- [ ] **Deployment gate:** protect `main`, require the workflow `test` job before
  production deployment, require production-environment approval, and review
  changes to browser source, Worker code, templates, CSP/build tooling,
  workflows, migrations, and vendored crypto.
- [ ] **Cloudflare identity/WAF:** verify the Worker receives the
  `CF-Connecting-IP` header on both preview and production; reject or alert on
  missing edge identity; add a coarse WAF/rate-limit rule for API traffic and
  random vault IDs; monitor 404/429 rates, unique IDs, D1 reads, recovery
  failures, Worker errors, and vault count without logging secrets.
- [ ] **Cloudflare credentials:** scope the production API token to the minimum
  Worker/D1 deployment permissions, rotate it, and keep it only in the protected
  production environment. Disable any unnecessary `workers.dev` route and
  verify the custom domain is the only production hostname.
- [ ] **Imported data verification:** after importing the existing capsule set,
  rerun the complete generated chunk set if any file boundary failed, then
  compare every D1 row's lookup ID, format, `length(blob)`, and SHA-256 with the
  private manifest. Keep the manifest and SQL dump offline and destroy them
  according to the retention record.
- [ ] **Legacy closure:** before 2027-01-26, notify users, resolve failed
  recoveries, take and verify the required encrypted/export and D1 recovery
  backups, then deploy a forward migration that drops `legacy_capsules` and a
  release that removes the migration page and endpoint. Verify D1 Time Travel,
  backups, logs, generated chunks, terminal history, and operator copies are
  removed or retained only under an approved encrypted retention policy.
- [ ] **HTTPS verification:** after deployment, probe HTTP and HTTPS for `/`,
  `/index.html`, `/legacy-migration`, `/migrate`, and API paths. Confirm HTTPS
  redirect, HSTS, CSP, `no-store`, CORS behavior, and that asset requests pass
  through the Worker as configured.

## Explicit residual risks

- **SA-03:** capsules cannot retroactively repair a previous disclosure of the
  legacy database. Assume all recovered legacy contents and credentials were
  exposed; notify affected users and require rotation of every important or
  reused credential. Quarantine/destroy old dumps and review historical logs.
- **SA-10 / L6 / L7 / L15:** a party that can rewrite the Worker/D1 can replay a
  genuine older ciphertext, permanently squat a learned vault identifier after
  deletion, or falsify the page fingerprint. The application has no trusted
  monotonic server-independent checkpoint. Require encrypted exports and
  independently published signed release hashes; treat unexpected revision
  rollback or a leaked vault ID as an incident and rotate/delete the affected
  vault.
- **External platform controls:** Cloudflare rate limits are local and
  eventually consistent; WAF coverage, GitHub branch protection, environment
  approvals, token scope, backup retention, browser/OS compromise, and the
  correctness of vendored cryptography require operational review and are not
  claimed to be fixed by source changes.
