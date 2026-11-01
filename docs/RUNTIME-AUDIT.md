# Runtime waste audit

Baseline: `339c323b9c5e1b18288e2015f34038f021716e66` on `main`.
Measurements used Node.js 24.22.1, npm 11.19.1, Prisma 6.14.0 and a disposable
PostgreSQL 17.11 container. All data was synthetic. No external database was used.
Counts below are observations, not latency estimates.

## Fixed paths

### Blocking key derivation during 2FA

Every encryption or decryption of a 2FA secret performed one synchronous
PBKDF2 derivation with 200,000 iterations on the event loop. This occurs during
2FA login, confirmation, initial setup, retrieval of an existing setup and reset.

The regression fixture performs 16 encryptions, 16 decryptions and two decryptions
of legacy ciphertext. Before: **34 synchronous, zero asynchronous KDF calls**.
After: **zero synchronous, 34 asynchronous KDF calls**. The same work now runs in
the crypto worker pool. It does not eliminate the KDF's CPU cost.

`tests/encryption.test.cjs` spies on the real crypto functions and asserts these
counts and the original iteration count, key length and digest. It also checks
salt uniqueness, both key versions, legacy ciphertext compatibility in both
directions, tamper rejection and missing-key errors. `tests/authController2FA.test.cjs`
exercises setup, confirmation, login, existing setup and reset with real crypto
and a mocked database, including rejection handling.

All controller callers await the result. The ciphertext format, salts, key
versions, AES-GCM authentication and password bcrypt cost remain unchanged.
Three encryption helpers that had no external callers are now internal functions.

### Independent Prisma clients

Importing the auth controller, passkey controller and cleanup service constructed
**three clients**. Each could initialize its own connection pool when first used.
These were module-level allocations, not allocations on every request.

All three modules now import one shared client. The constructor spy in
`tests/runtimeWaste.test.cjs` counts **three before, one after**, and verifies
that 1,000 access-token checks perform no database lookups or new client allocations.
Socket counts and pool memory were not measured.

### Unused user fetch on refresh

Refresh-token rotation included the entire related user record, then used only
the token's own `userId`. The real Prisma query-event measurement found **two
SELECTs per refresh, including one user SELECT**, before the change. After
removing the include: **one SELECT, zero user SELECTs**. The delete/create
transaction and token expiry checks remain unchanged.

The mock regression runs 100 refresh requests: **100 user relations requested
before, zero after**, with the same 100 lookups and 200 rotation writes.
`scripts/measure-database.cjs --check` also asserts the real SQL counts against a
disposable database. Invalid and expired-token tests still reject without writes.

### Cleanup scan and redundant indexes

Refresh-token cleanup uses `expiresAt < now` but had no index on `expiresAt`.
The default schedule runs daily at 02:00 in the configured timezone. With 100
expired rows among 100,000 refresh tokens, PostgreSQL's `EXPLAIN (ANALYZE, BUFFERS,
FORMAT JSON)` showed:

- Before: sequential scan, 100 matches and **99,900 rows removed by the filter**.
- After adding the expiry index: index scan, **100 rows visited**, zero index
  rechecks rejected.

The fixture fixes the cutoff date between the expired and live timestamps to
keep the counts reproducible. Deletion criteria and scheduling are unchanged.
PostgreSQL may still choose a sequential scan if most tokens are expired; that
is a useful scan rather than wasted work.

The schema also declared nonunique indexes on `Passkey.credentialId` and
`Challenge.challenge` alongside their unique indexes on those same columns.
The database catalog contained **two indexes per credential/challenge key
before, one after**. Each removed index was unnecessary storage and index upkeep
on inserts and deletes. Physical write counts were not measured. Uniqueness and
lookup support remain provided by the original unique indexes.

The new migration adds the expiry index and drops only the redundant nonunique
indexes. The database measurement's `--check` mode asserts the indexed cleanup
plan, the surviving 99,900 live rows, and retention of the unique indexes.

## Reproduce the checks

The ordinary tests never connect to a database:

```sh
npm ci
npx prisma generate
npm test
```

The new count tests were also run against the unchanged baseline implementation:
`node --test tests/runtimeWaste.test.cjs tests/encryption.test.cjs` failed the
three intended assertions (client count, relation fetches and synchronous KDFs).
All pass after the fixes.

The optional database measurement refuses non-loopback addresses, other database
names and alternate schema parameters. Use a new, empty disposable database.
This command sequence creates one with memory-backed data:

```sh
docker run --detach --rm --name node-auth-runtime-audit \
  --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_DB=node_auth_waste_audit -e POSTGRES_PASSWORD=audit-only-password \
  -p 127.0.0.1::5432 postgres:17-alpine
docker exec node-auth-runtime-audit pg_isready -U postgres
audit_port=$(docker port node-auth-runtime-audit 5432/tcp | cut -d: -f2)
export AUDIT_DATABASE_URL="postgresql://postgres:audit-only-password@127.0.0.1:${audit_port}/node_auth_waste_audit"
DATABASE_URL="$AUDIT_DATABASE_URL" npx prisma migrate deploy
npx prisma generate
npm run build
node scripts/measure-database.cjs --check
docker rm --force node-auth-runtime-audit
```

Run the database commands after `pg_isready` reports ready. The script creates
and removes only its synthetic user and cascade-owned tokens. Without `--check`,
it reports counts and plans for baseline comparisons. The audit applied the new
migration to a baseline-schema database for before/after measurements, and also
successfully applied the complete nine-migration history to a second empty database.

## Checked and rejected

- Access-token middleware checks JWTs without a database query or password KDF.
  The 1,000-request fixture confirms zero database lookups and zero client allocations.
- Password hashing and comparison already use asynchronous bcrypt. Cost 12 at
  login/registration and password-protected management actions is intentional.
- There is no per-item database query loop. Passkey options fetch one user's
  credentials; all credentials are needed for allow/exclude lists. Listing is
  user-scoped and selects response fields. Arbitrary truncation would change
  behaviour. Typical account-size latency was not measured.
- Email, token and credential lookups already have unique indexes; user-scoped
  token/passkey queries have user-ID indexes. No additional composite index was
  justified by the query predicates.
- Cleanup is two set-based deletes daily, with an overlap guard. Challenge
  expiry was already indexed. There is no application polling loop, retry queue,
  per-request subprocess, file copy or disk-write path to remove.
- The rate limiter uses the dependency's expiring memory store. A synthetic
  10,000-IP fixture retained 10,000 entries initially and zero after two explicit
  window rotations. Its timer is unrefed; it does not retain clients forever or
  keep the process alive. Semantics and windows are unchanged.

## Limits and unrelated observations

- No CI workflow exists. `npm test` builds TypeScript and runs all 20 Node tests.
  Adding CI is a useful follow-up, outside this change.
- `npm ci` reported 13 dependency vulnerabilities (one low, 12 high). Dependency
  remediation was outside this runtime audit.
- An optional stricter compiler run, `npx tsc --noEmit --noUnusedLocals
  --noUnusedParameters`, reports three pre-existing unused request parameters in
  `src/controllers/helloController.ts` and `src/index.ts`. The configured build passes.
- `BackupCode` has no runtime consumers. Its table was retained because dropping
  stored data is outside this audit. The exported `AppConfig` type also has no
  in-repository consumers.
- Existing 2FA setup retrieval passes a base32 secret to `speakeasy.otpauthURL`
  without specifying base32 input encoding. With a synthetic secret, the returned
  QR URI contains a different secret. Initial setup/reset use a different path.
  This pre-existing correctness issue was left unchanged.
- The existing passkey migration stores `deviceType` as text while the Prisma
  schema declares an enum. This schema-history mismatch predates this change;
  the index migration applies successfully with either representation.
- Asynchronous PBKDF2 still occupies the shared worker pool under load. No KDF
  strength, token lifetime, rate limit, cleanup cadence or auth policy was changed.
- Building/dropping indexes can acquire database locks. The migration was only
  exercised on disposable databases; production lock duration was not measured.
