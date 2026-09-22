# Cert-Reflex

Cert-Reflex issues short-lived TLS certificates from its own CA, watches them,
and replaces them before they expire (or the moment someone corrupts one on
disk) without dropping a single connection on the HTTPS listeners they protect.
Detect, remediate, verify, no human in the loop.

Three HTTPS listeners run inside one Spring Boot process, each with its own
certificate valid for two minutes. A watcher scans every five seconds. When a
certificate has under thirty seconds left, or no longer matches what the
inventory says should be on disk, it is reissued and hot-swapped in about 100ms.
The CA's private key never leaves KMS; the issuer sends a digest and gets back a
signature.

This is a weekend-scoped demo, not a production PKI system. It is built to be
watched for two minutes and then read.

## See it work

https://github.com/user-attachments/assets/731c3fdb-2761-4169-a5d7-22c5d42938ba

30 seconds, no narration: three listeners on two-minute certificates, a
certificate corrupted on disk, the expiry path on another listener, and each
one detected and reissued while the others stay green. The file is also at
[docs/cert-reflex-demo.mp4](docs/cert-reflex-demo.mp4).

The zero-downtime proof is deliberately not in the recording: a terminal beside
the dashboard is illegible at this size. Walkthrough step 3 below covers it in
one command.

## Running it

Requires Docker and a JDK 21+. Node.js is **not** required, because the
dashboard's build output is committed.

```bash
docker compose up -d --wait
./scripts/create-ca-key.sh
./mvnw spring-boot:run
```

Then open the dashboard:

```
http://localhost:8080/dashboard
```

`--wait` is not optional. Without it, `create-ca-key.sh` can run before
LocalStack is accepting requests and fail.

Throughout, use `--cacert runtime/ca.pem` rather than `curl -k`. These are real
CA-signed certificates, and `-k` throws away your ability to see that:

```bash
curl --cacert runtime/ca.pem https://localhost:8443/
openssl verify -CAfile runtime/ca.pem runtime/demo-a/cert.pem
```

The dashboard is served on the HTTPS listeners too, which is a quick way to see
the chain is genuine:

```bash
curl --cacert runtime/ca.pem https://localhost:8443/dashboard
```

| Address | Serves |
|---|---|
| `http://localhost:8080` | dashboard and admin API |
| `https://localhost:8443` | listener `demo-a` |
| `https://localhost:8444` | listener `demo-b` |
| `https://localhost:8445` | listener `demo-c` |

## Stopping and resetting

```bash
docker compose down -v
```

Use `-v`. Without it you get a half-reset stack that cannot start: LocalStack
never persists the CA key, so stopping it destroys the key, while `.env` still
names the old one. The next `./mvnw spring-boot:run` then dies during startup
with:

```
Key 'arn:aws:kms:us-east-1:000000000000:key/…' does not exist
```

`-v` clears the database too, so the next start is the clean first-run sequence
above and everything is reissued from scratch. `runtime/` is regenerated
automatically and can be deleted freely; only `.env` is worth keeping, and
`./scripts/create-ca-key.sh` rewrites that anyway.

If you already stopped without `-v`, re-run `./scripts/create-ca-key.sh` and
start again; it detects the stale key id and replaces it. If the application
was left running while LocalStack went away, see the LocalStack entry under
[Troubleshooting](#troubleshooting) instead: the rows will have gone to `FAILED`
and need a manual rotate each.

## A two-minute walkthrough

**1. Watch it run.** Open `http://localhost:8080/dashboard`. Three panels count
down from 120 seconds. At 30 seconds a panel turns amber and holds for five
seconds, then flashes blue as the rotation completes and the countdown snaps
back to full. Nothing is being triggered; that is the system maintaining itself.

**2. Break one.** Click `corrupt` on a panel, or:

```bash
./scripts/inject-failure.sh demo-b CORRUPT
```

This overwrites `runtime/demo-b/cert.pem` with random bytes and touches nothing
else. Within about ten seconds the panel goes red, the event log fills in
`Injected`, `Detected corrupted`, `Issuing`, `Swapped`, and the panel returns to
green with a new serial.

**3. Prove there was no downtime.** This one needs two terminals, in order.

First, start a keep-alive session: twenty requests, one per second, all on one
connection. `[1-20]` is curl's own URL range, so the shell never sees it:

```bash
curl -v --cacert runtime/ca.pem --keepalive-time 60 --rate 60/m \
  "https://localhost:8443/?[1-20]"
```

That gives you about twenty seconds. While it is still running, rotate from a
second terminal:

```bash
curl -X POST http://localhost:8080/internal/certs/demo-a/rotate
```

The verbose output shows one TCP connect, one TLS handshake, `Re-using existing
connection` for every subsequent request, and every response a 200, while the
serial in the response body changes partway through. The connection that was
already open never noticed.

`--rate` needs curl 7.84 or newer (mid-2022); `curl --version` will tell you. On
an older curl the twenty requests fire in under a tenth of a second, no rotation
can land inside the session, and the unchanged serial looks like a rotation that
did not work.

Stay under 100 requests per session. Tomcat's `maxKeepAliveRequests` defaults to
100, so a longer run shows a reconnect at exactly request 101 that looks like a
dropped connection and is not.

**4. Break the other way.** Click `expire` on a different panel, or:

```bash
./scripts/inject-failure.sh demo-a EXPIRE
```

This backdates the inventory row's `not_after` and leaves the file alone, so it
exercises the expiry path instead of the corruption check. The two are
distinguishable in the dashboard's status column and in the event log.

**5. Look at the state directly.**

```bash
curl -s http://localhost:8080/internal/certs | python3 -m json.tool
curl -s http://localhost:8080/internal/events | python3 -m json.tool
```

## What it does, and what was deliberately cut

Built:

- A minimal intermediate CA issuing short-lived EC P-256 certificates, signed
  through LocalStack KMS so the CA private key never enters the process
- A watcher that detects certificates near expiry or no longer matching the
  inventory
- A remediator that reissues and hot-swaps with no dropped connections
- Three demo HTTPS listeners, each with its own certificate, owned end to end
- Failure injection for both expiry and corruption, via endpoint and script
- A certificate inventory and event log in Postgres
- A single-screen dashboard: live status per listener, event feed, break-it
  controls

Deliberately out of scope:

- Revocation (CRL/OCSP)
- Multi-CA hierarchy or cross-signing
- SSH certificates, RADIUS, FIDO2, or any other identity product surface
- A real HSM (LocalStack KMS stands in)
- Metrics and observability dashboards
- Authentication on the admin API, including the break-it controls; this runs
  locally and is captured as a recording rather than hosted
- Automatic retry of a failed rotation; manual rotation is the recovery path
- Multi-instance operation: ShedLock is present and the lock is real, but
  startup recovery assumes a single instance

## Architecture

```
                    ┌──────────────────┐
                    │  Watcher          │  @Scheduled every 5s
                    │  + ShedLock       │  marks, then remediates next pass
                    └────────┬──────────┘
                             │ near expiry, or on-disk key != inventory
                             ▼
                    ┌──────────────────┐
                    │  Remediator       │
                    └────────┬──────────┘
                             │ issue for service_name
                             ▼
                    ┌──────────────────┐        ┌───────────────────┐
                    │  Issuer (CA)      │──────▶│  LocalStack KMS    │
                    │  Bouncy Castle    │ digest │  EC P-256 key      │
                    └────────┬──────────┘        └───────────────────┘
                             │ signed leaf + locally generated leaf key
                             ▼
                    ┌──────────────────┐
                    │  Write cert/key   │  then reload the connector
                    │  to watched path  │  explicitly (~60ms)
                    └────────┬──────────┘
                             ▼
                    ┌──────────────────┐
                    │  Demo listener    │  open connections unaffected,
                    │  serves new cert  │  new handshakes get the new cert
                    └──────────────────┘

         ┌────────────────────────────┐   ┌────────────────────────────┐
         │  Inventory + events         │   │  Admin API + dashboard      │
         │  (Postgres)                 │   │  (port 8080)                │
         └────────────────────────────┘   └────────────────────────────┘
```

State machine:

```
ACTIVE ──(under 30s left)────▶ EXPIRING ──▶ ROTATING ──▶ ACTIVE (new serial)
ACTIVE ──(on-disk mismatch)──▶ CORRUPTED ─▶ ROTATING ──▶ ACTIVE (new serial)
ROTATING ──(issue/install error)──▶ FAILED   (logged, not retried)
```

A process that dies mid-rotation leaves a row in `ROTATING`, which no scan
matches: the expiry scan looks at `ACTIVE` rows and the remediation scan at
`EXPIRING` and `CORRUPTED` ones. On startup those rows are reset to `CORRUPTED`,
which is honest (the row and the disk genuinely disagree) and hands them to the
loop that already works.

Detection and remediation happen in separate watcher passes. That costs one
five-second interval and buys an observable `EXPIRING` state: rotation itself
takes about 100ms, so a dashboard polling once a second would otherwise never
render it.

Every state transition commits in its own transaction. A rotation is
deliberately *not* wrapped in one, because the intermediate states are the
demonstration.

The full technical document is in
[docs/cert-reflex-project-doc.md](docs/cert-reflex-project-doc.md).

## Behaviour that looks wrong and is not

**Clicking `corrupt` appears to do nothing for a beat.** The inventory is
authoritative and lags reality by up to one watcher interval, because the system
genuinely has not noticed yet. Closing that gap is the watcher's whole job, and
watching it close is more honest than hiding it.

**A corrupted-but-parseable certificate is briefly served.** Spring's SSL bundle
watcher reloads whatever is on disk without an opinion about whether it is the
right certificate. The watcher's public-key check catches it a pass later.

**A corrupted certificate is not an outage.** The listener keeps serving its last
good certificate from memory, so corruption shows up in the dashboard, the event
log and the application log, but never on the wire.

**A red `Failed` panel is terminal.** Failed rotations are not retried, by
design. The panel says so, and manual rotation is the recovery path:

```bash
curl -X POST http://localhost:8080/internal/certs/demo-a/rotate
```

**The blue flash says "just rotated", not "rotating".** It marks a rotation that
completed. The live `ROTATING` state lasts 60–100ms, which a one-second poll
cannot reliably catch, so claiming otherwise would be decoration.

**Negative countdowns are real.** An expired certificate awaiting remediation,
or a row stranded by a failure, genuinely has negative time remaining.

## Where it diverges from the spec

The technical document was written before the build. Where the build disagrees
with it, the reason is below.

**No Spring Batch.** The watcher is a plain `@Scheduled` method wrapped in
ShedLock's `@SchedulerLock`. There are no batch semantics here and the metadata
tables are not worth their cost at a five-second cadence.

**Spring Boot 4.1.1.** The 3.5 line the spec assumed reached open-source end of
life on 30 June 2026, and shipping a security-adjacent demo on an EOL release
line is the wrong signal.

**`keyUsage` is `digitalSignature` only.** The spec also lists
`keyEncipherment`, which means RSA key transport and is meaningless on an EC
certificate.

**Self-registered connectors do not inherit SSL bundle reloads.** The spec
asserts `reload-on-update` is sufficient. It is, but only for the connector
Spring Boot builds from `server.*` properties. Connectors registered by the
application get the bundle but no update handler, so each listener registers
its own. Without that, a listener serves a stale certificate forever while the
inventory reports `ACTIVE`.

**An `INJECTED` event type beyond the spec's list.** An injection is an operator
action, not an observation. Reusing a detection type would put a detection line
in the log seconds before anything was detected, and the log exists to show when
the system noticed.

**The admin surface is unauthenticated and answers on all four connectors.**
Both are deliberate: the connectors share one servlet context, and this is run
locally and captured as a recording rather than hosted, which is the only reason
an unauthenticated "corrupt this certificate" button is acceptable. A hosted
deployment would bind the admin surface to 8080 alone and put auth in front of
it.

## Measured behaviour

All measured on one laptop, not estimated:

- **6.9s** from `docker compose up` to three listeners serving CA-signed
  certificates, from a dropped volume and an empty `runtime/`, with the
  container images already pulled; a first run adds that download
- **21 rotations in ten minutes** unattended, nothing at WARN or ERROR
- **6,699 requests** across the three listeners during live rotations: zero
  failures, zero dropped connections
- **~60ms** for the explicit connector reload, **~100ms** for a full rotation
- **~10s** from corrupting a file to a fresh certificate on the wire, almost
  all of it the two watcher passes

## Troubleshooting

**`FATAL: role "pki" does not exist`**

Something already owns port 5432 and is shadowing the container, so the app is
talking to a different Postgres. The error names the role, not the cause. Point
the container at another port:

```bash
echo 'DB_PORT=55432' >> .env
docker compose up -d --wait
```

`docker-compose.yml` and `application.yml` both already read `DB_PORT`.

**Every rotation fails after restarting LocalStack**

LocalStack does not persist KMS keys, so restarting it destroys the CA key while
`.env` still points at the old id. Rotations then fail, and because failed
rotations are not retried, the fleet stays stranded. Recovery is three steps:

```bash
./scripts/create-ca-key.sh                     # detects the stale id, makes a new key
# restart the app so the CA certificate is re-minted against it
for s in demo-a demo-b demo-c; do
  curl -X POST http://localhost:8080/internal/certs/$s/rotate
done
```

**Placeholder certificates left in `runtime/` after a failed first start**

Bootstrap writes self-signed placeholders before the application context
finishes coming up, so Tomcat has something to bind to. If startup then fails,
those files remain. This is harmless; the next successful boot replaces them
with CA-signed certificates within seconds.

## Layout

```
docker-compose.yml                  Postgres 16 and LocalStack (KMS)
scripts/create-ca-key.sh            creates the CA signing key, writes .env
scripts/inject-failure.sh           inject EXPIRE or CORRUPT for a service
scripts/build-dashboard.sh          rebuilds ui/ into the committed output (developers only)
src/main/java/dev/atharva/certreflex/
  issuer/                           CA certificate, leaf building, KMS content signer
  inventory/                        certs table access and the state transitions
  events/                           event log
  watcher/                          scheduled scan and the on-disk corruption check
  remediator/                       rotation
  demo/                             the three HTTPS listeners and the installer
  admin/                            admin API and failure injection
  bootstrap/                        two-stage startup and stale-rotation recovery
src/main/resources/db/migration/    Flyway schema
src/main/resources/static/dashboard/  committed dashboard build
ui/                                 dashboard source (React, Vite)
runtime/                            certificates and keys, gitignored
```

## Tests

```bash
./mvnw verify
```

One integration test covers the issuer against real Postgres and LocalStack
containers via Testcontainers, with no mocking of KMS, since testing against
the real API shape is the reason LocalStack is here. One unit test covers the
corruption check, which is the only piece of logic subtle enough that a silent
mistake in it would look like a healthy system. The watcher and remediator are
exercised by running the demo.
