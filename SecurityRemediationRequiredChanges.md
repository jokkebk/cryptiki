# Security remediation review: required changes

Date: 2026-07-28  
Reviewed revision: `2d1e644`

## Verdict

I am not ready to accept `SecurityRemediationChecklist.md` as complete. The
remediation materially improves the Worker, deployment workflow, document
bounds, CSP, and legacy import path, and the current test suite passes 22/22.
However, several checked-off findings are either still unresolved or were
regressed by the fix. In particular, the browser workflows are not executed by
the test suite, which allowed broken exports and incomplete failure handling to
be described as fixed.

The unchecked operator actions in `SecurityRemediationChecklist.md` remain
mandatory. The items below are additional code, test, or documentation changes
needed before the checklist can be treated as an accurate release gate.

## Release blockers

### 1. Capsule deletion is authorized by the lookup ID alone

**Affected disposition:** SA-05 / M5  
**Evidence:** `src/worker.js:158-183`, especially `src/worker.js:172-176`;
`src/migration.js:130-132`; `migrations/0002_legacy_capsules.sql:1-7`

`DELETE /api/legacy/recover` accepts `{lookupId}` and deletes the row without
any separate proof. This is exactly the destructive design SA-05 warned
against. A lookup ID is an address used for recovery, not a deletion
capability. Full lookup IDs exist in the private import manifest and can also
be exposed by request, support, database, or operator tooling. Disclosure now
allows permanent denial of recovery even though it does not reveal the capsule
decryption key.

Required changes:

- Derive a separate, domain-separated deletion capability during capsule
  construction.
- Store only its hash in D1 and require the raw capability for deletion.
- Delete with a conditional query covering both lookup ID and capability hash;
  preserve a generic response for wrong or missing capabilities.
- Add a forward migration for the new column. Do not edit or remove migration
  `0002`.
- Rebuild/reimport the live capsule set so existing rows have deletion
  authorization material.
- Test that a lookup ID alone and a wrong capability cannot delete, while the
  correct capability can delete only its own capsule.

### 2. Both encrypted-export paths are broken

**Affected disposition:** SA-08; SA-10 recovery controls  
**Evidence:** `src/client.js:243-258`, `src/client.js:272-274`,
`src/client.js:321-322`

The normal export button assigns `exportVault` directly as its event handler.
The browser therefore passes a click `Event` as the function's `doc` argument,
and `encrypt()` rejects it as an invalid vault document.

The conflict path passes `mine`, but `saveVault()` supplied the already
encrypted `Uint8Array`, not the document. `exportVault()` tries to validate and
encrypt that byte array as a document and fails for the same reason. Thus the
claimed normal/conflict export-import round trip does not exist, and the main
user-controlled recovery mechanism is unavailable.

Required changes:

- Bind the normal button with `() => exportVault()` so the default document is
  used.
- Capture/pass the conflicting plaintext document (or construct the final
  export envelope directly), never pass a v3 ciphertext where a document is
  expected.
- Surface asynchronous export errors in the UI.
- Add browser-level tests proving that normal and conflict exports download,
  decrypt, validate, and import through the normal import path.

### 3. Credential rotation is still unsafe under ambiguous network failure

**Affected disposition:** SA-01 / M2  
**Evidence:** `src/client.js:278-300`

The pending rotation is recorded only after `DELETE` returns a non-success HTTP
response. If the Worker deletes the old vault but the response is lost,
`fetch()` rejects and no pending state is retained. The UI continues using the
now-deleted old keys. A retry can become stuck because a subsequent old-vault
delete returns 404, which is treated as failure forever.

The new credential values also remain in the closed dialog after submission;
`lock()` does not clear the credential-dialog fields.

Required changes:

- Record the verified target and pending source deletion before issuing the
  destructive request.
- Make an ambiguous delete resumable. Once the target document is verified, an
  authenticated 404 for the previously unlocked source can be treated as
  already deleted, or resolved through an explicit verification step.
- Attempt target verification after an ambiguous create response rather than
  assuming creation failed.
- Clear new credential fields on success, failure, cancel, and lock.
- Offer a working encrypted export before source deletion.
- Add failure-injection browser tests after target POST, target GET, and source
  DELETE, including “server committed but response was lost.”

### 4. The migration flow bypasses v3 credential policy and is not resumable

**Affected disposition:** M8; SA-01 principles; SA-07  
**Evidence:** `src/migration.js:114-136`, `src/migration.js:142-144`

The main client enforces `strongCredentials()`, but the migration page accepts
any non-empty new name/password pair. A user can therefore migrate directly
into a weak v3 vault even though M8 is checked off.

The migration POST treats every 409 as fatal and clears recovered state. If the
POST committed but its response was lost, a retry cannot verify/resume the
existing target. This can leave an orphaned v3 vault and an unconsumed capsule.

The advertised 60-second hidden-page lock is also not a 60-second lock:
`visibilitychange` merely records the time and clears state when the user later
returns. While the page remains hidden, recovered plaintext can remain in
memory/DOM until the ordinary 15-minute timer fires (and background timer
throttling can make that longer).

Required changes:

- Apply the same named credential policy and user guidance in both the main and
  migration clients, preferably from one shared definition.
- On 201, 409, or an ambiguous POST failure, read the target with the proposed
  authorization, decrypt it, and compare the exact expected document before
  deciding whether creation can resume.
- Keep cleanup retry material until capsule deletion is confirmed; do not tell
  the user that an operator must remove a capsule after clearing the only
  actionable identifier/capability.
- Start a dedicated short lock timer when the page becomes hidden and clear it
  only if the page becomes visible before the deadline.
- Add browser tests for weak credentials, ambiguous creation, resumable
  cleanup, hidden-tab expiry, inactivity expiry, manual lock, and all sensitive
  field clearing.

## Other required corrections

### 5. Main-client import input is still unbounded before decoding

**Affected disposition:** SA-11 / M9 / L13  
**Evidence:** `src/client.js:16`, `src/client.js:69-74`,
`src/client.js:274`

Decompression output is bounded, but `importVault()` calls the unbounded main
client `unb64()` for the pasted export blob. A very large string is decoded and
allocated before any ciphertext-size check. This does not satisfy SA-11's
requirement to reject oversized base64 before decoding.

Required changes:

- Give the main client a strict base64url decoder that validates syntax and
  rejects encoded length above the 128 KiB envelope limit before calling
  `atob()`.
- Enforce the same bound on vault API responses before decoding.
- Add boundary and oversized-import tests.

### 6. Saved offline HTML still records the search query

**Affected disposition:** SA-12 / M6  
**Evidence:** `src/client.js:132-143`, `src/client.js:309-318`

When a search has no matches, the live `#empty .big` node contains
`Nothing matches “<query>”.` `saveApp()` clears the search input but does not
restore this node, so the saved HTML can contain a service name, username,
note fragment, or other secret search term. The checklist's claim that dynamic
values are reset is therefore false.

Required changes:

- Prefer generating the offline file from a pristine assembled template.
  Otherwise reset every dynamic text, attribute, class, visibility state, and
  form property, including the empty-result text and hint.
- Add a canary browser test that places distinct secrets in every input,
  textarea, search result/empty message, toast, status, note label, title, and
  ARIA attribute and asserts that none occur in the downloaded bytes.

### 7. The capsule builder still overwrites existing secret output paths

**Affected disposition:** SA-13  
**Evidence:** `tools/build-legacy-capsules.mjs:1-2`,
`tools/build-legacy-capsules.mjs:166-170`

The importer uses exclusive `0600` creation, but the builder still uses
`writeFileSync(path, ..., {mode: 0o600})` followed by `chmodSync`. An existing
file is truncated before chmod, and a symlink is followed. This leaves the
local artifact issue from SA-13 partly unresolved.

Required changes:

- Reuse an exclusive `openSync(path, "wx", 0o600)`/file-descriptor write helper
  for the builder output.
- Refuse existing paths and add tests for existing files, unsafe modes, and
  symlinks.

### 8. The rate-limit documentation overstates what the code enforces

**Affected disposition:** SA-02 / H1 / H2 / M10  
**Evidence:** `src/worker.js:112-134`; `README.md:30-34`;
`SecurityRemediationChecklist.md:14-16`

The pre-D1 actor limiter is a good and important fix. However,
`AUTH_LIMITER` is keyed as `${actor}:${id}`, not by vault ID alone. It is a
per-actor-per-vault limit, so there is no cross-actor per-vault limit despite
the checklist and README claiming one. Distributed traffic can still multiply
D1 reads against one target.

Required changes:

- Either implement and test a carefully chosen separate resource/vault control,
  or explicitly document and accept the distributed residual risk and make the
  WAF/operator control a deployment blocker.
- Correct “per-vault” claims unless/until a limiter keyed independently of the
  actor exists.
- Test the intended behavior with multiple actor identities against one vault.

### 9. The closure runbook says to remove an applied migration

**Affected disposition:** SA-05 lifecycle  
**Evidence:** `README.md:128-137`

The README tells the operator to remove migration `0002` at closure. Applied
migrations are immutable history; SA-05 correctly called for a new forward
migration that drops `legacy_capsules`.

Required changes:

- Keep `0002_legacy_capsules.sql`.
- At closure, add a new dated forward migration that drops the table, while
  removing the page and endpoint in the same release process.
- Correct the README's description of `/api/legacy/recover` as “read-only”;
  after the deletion redesign it will have an authenticated consume operation.

## Test-gate correction

`SecurityRemediationChecklist.md:5` says the code fixes are covered by the
repository test suite. That is not currently true. The suite executes crypto
core and Worker tests and performs static checks on assembled HTML, but it does
not execute the behavior in `src/client.js` or `src/migration.js`. This is why
the export argument bugs, saved-app leak, rotation ambiguity, migration policy
bypass, and hidden-page timing issue all pass CI.

Before re-checking the affected findings, add a browser-level security suite
that covers at least:

- normal and conflict export/import round trips;
- saved-app canary-secret removal and embedded CSP;
- rotation failure injection at every network boundary;
- migration create/resume/consume failure injection;
- credential policy parity between both clients;
- inactivity, hidden-page, manual, success, and failure clearing;
- maximum encoded, encrypted, compressed, decompressed, document, and field
  sizes; and
- deletion authorization for migration capsules.

Until those tests exist and the blockers above are fixed, the corresponding
`[x]` entries in `SecurityRemediationChecklist.md` should be changed back to
unchecked or marked partial.
