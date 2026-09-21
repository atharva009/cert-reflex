# Cert-Reflex: Technical Specification

*This is a seed document for a build, not a phased plan. It defines what the system is, how its pieces fit together, and what's explicitly out of scope. Sequencing the work into phases is intentionally left open.*

## 1. What This Is

**Cert-Reflex**: a service that detects certificates approaching expiry or corruption and rotates them automatically, with zero dropped connections on the endpoints they protect. Detect, remediate, verify, no human in the loop.

Weekend-scoped demo, not a production PKI system.

## 2. Why This Project

- **Extends real prior work.** The Ribbon SRE agent already does detect-and-remediate without human intervention, pointed at infrastructure failures. This applies the same pattern to certificates.
- **Targets a real pain point.** Certificate expiry causes real outages, and PKI operations are a burden most teams don't want to own. This is a miniature version of the actual problem, not an abstract crypto exercise.

## 3. Scope

### In scope
- A minimal intermediate CA that issues short-lived certificates
- A watcher that detects certs nearing expiry or corrupted on disk
- A remediator that renews and hot-swaps the cert with zero dropped connections
- 3 to 4 demo HTTPS listeners, each with its own cert, owned end to end by this system
- A failure-injection endpoint/script covering both expiry and corruption
- A cert inventory table (Postgres)
- A single-screen dashboard UI: live status per listener, a running event log, and buttons to break things on demand (see Section 5.7)

### Explicitly out of scope
- Revocation (CRL/OCSP)
- Multi-CA hierarchy or cross-signing
- SSH certs, RADIUS, FIDO2, or any other identity product surface
- A real HSM (LocalStack KMS stands in, see Section 6)
- Metrics/observability dashboard (first thing to cut if time runs short)

State this list explicitly in the README. Knowing what was deliberately cut is itself a signal.

## 4. High-Level Architecture

```
                    ┌──────────────────┐
                    │   Watcher Job     │  Spring Batch, scheduled every 5s
                    │   + ShedLock      │
                    └────────┬──────────┘
                             │ finds cert nearing expiry or corrupted
                             ▼
                    ┌──────────────────┐
                    │   Remediator      │
                    └────────┬──────────┘
                             │ requests new cert for service_name
                             ▼
                    ┌──────────────────┐        ┌───────────────────┐
                    │   Issuer (CA)     │──────▶│  LocalStack KMS    │
                    │  Bouncy Castle    │  sign  │  EC P-256 key      │
                    └────────┬──────────┘        └───────────────────┘
                             │ signed leaf cert + freshly generated leaf key
                             ▼
                    ┌──────────────────┐
                    │  Write cert/key    │  Spring Boot SSL bundle
                    │  to watched path   │  (reload-on-update: true)
                    └────────┬──────────┘
                             ▼
                    ┌──────────────────┐
                    │  Demo listener     │  connection stays open,
                    │  hot-reloads       │  cert changes underneath it
                    └──────────────────┘

              ┌────────────────────────────┐
              │  Cert Inventory (Postgres)  │  read/written by watcher, issuer, remediator
              └────────────────────────────┘

              ┌────────────────────────────┐
              │  Admin API                  │  list certs, manual rotate, inject failure
              └────────────────────────────┘
```

## 5. Component Detail

### 5.1 Issuer (CA)

- CA signing key lives in LocalStack KMS as an asymmetric key, `KeyUsage: SIGN_VERIFY`, `KeySpec: ECC_NIST_P256`. The private key material never leaves KMS.
- For each issuance: generate a fresh EC P-256 **leaf** key pair locally (this key is not protected, it has to live in the process to terminate TLS). Build the TBSCertificate with Bouncy Castle's `JcaX509v3CertificateBuilder`.
- Signing: implement a custom `ContentSigner` whose `getSignature()` does not sign locally. Instead it takes the SHA-256 digest of the TBS bytes and calls KMS `Sign` with `MessageType: DIGEST`, `SigningAlgorithm: ECDSA_SHA_256`, using the CA key ID. The returned DER-encoded signature is what goes into the final certificate.
- Cert extensions: `BasicConstraints` (CA:false for leaf), `KeyUsage` (digitalSignature, keyEncipherment), `ExtendedKeyUsage` (serverAuth), `SubjectAlternativeName` set to the demo listener's hostname.
- Output: leaf certificate PEM (plus CA chain) and leaf private key PEM, written to the file path the target listener's SSL bundle watches.

### 5.2 Inventory (Postgres)

One row per managed cert. See Section 6 for the schema. Private key material is never persisted to the database, only a file path reference. The certificate PEM itself is fine to store, it's public.

### 5.3 Watcher

Spring Batch tasklet on a fixed schedule (every 5 seconds, given a 2-minute validity and 30-second rotate threshold, this needs to be frequent enough to reliably catch the window). Each run:

1. Scans inventory for rows where `not_after - now() < rotate_threshold`, or where the on-disk cert fails to parse or its public key doesn't match the inventory record (corruption check).
2. Marks matching rows `EXPIRING` or `CORRUPTED`.
3. Hands off to the remediator.

`ShedLock` wraps the scheduled method (`@SchedulerLock(name = "cert-watcher", lockAtLeastFor = "PT2S", lockAtMostFor = "PT30S")`) so a second instance, if one ever existed, wouldn't race to rotate the same cert.

### 5.4 Remediator

1. Calls the issuer for a fresh cert for the affected `service_name`.
2. Writes the new cert and key to the exact file paths configured for that listener's SSL bundle.
3. Spring Boot 3.2+'s SSL bundle `reload-on-update` picks up the file change and reloads the connector's SSL context in place. Active connections are not dropped, only new handshakes see the new certificate.
4. Updates the inventory row to `ACTIVE` with the new serial and validity window.

### 5.5 Demo Listeners

One Spring Boot process, 3 to 4 additional embedded Tomcat connectors, each bound to its own port and its own named SSL bundle. Added via a `WebServerFactoryCustomizer<TomcatServletWebServerFactory>` that registers extra `Connector` instances at startup, each pointed at a distinct `SSLHostConfig`/bundle name (`demo-a`, `demo-b`, etc). The inventory table, not the process topology, is what proves this is managing a fleet.

### 5.6 Failure Injector

Two failure types, exposed via a small admin endpoint (`POST /internal/failures/{serviceName}?type=EXPIRE|CORRUPT`), backed by a shell script that just curls it:

- **EXPIRE**: directly rewrite the inventory row's `not_after` to a timestamp already in the past, so the watcher picks it up on its next pass.
- **CORRUPT**: overwrite the on-disk cert file with garbage bytes, so the watcher's parse check fails.

Both should be visibly distinguishable in the logs and in the inventory's `status` column, so a reviewer watching the demo can tell which failure was injected and how it was caught.

### 5.7 UI (Dashboard)

A React SPA (Vite), built once with its static output committed into `src/main/resources/static/dashboard/`, so a reviewer who clones the repo gets it working without installing Node.js. The `ui/` source stays in the repo for anyone who wants to see how it's built. It polls the Admin API (`GET /internal/certs` and `GET /internal/events`, see Section 7) every second.

This is a local-only demo tool, captured as a recording for the README, not a publicly hosted app (see Section 11 for why), so it can freely expose the break-it controls without needing an auth layer in front of them.

**Design brief** (subject: an operations console for watching a security system detect and heal itself in real time; audience: someone watching a recording or your screen for under two minutes; job: make a state change unmistakable the instant it happens):

- **Color:** dark graphite background (`#161A1F`), not a stock near-black. Status carried by four working colors, not decoration: `#5FB88A` active, `#E0A23D` expiring, `#E0623D` corrupted/failed, `#4A9DE0` rotating. Each listener panel's left border and status word use this color, nothing else on the page competes for color attention.
- **Type:** one sans for structure (labels, panel titles, log prose, e.g. IBM Plex Sans or similar, sentence case throughout, no tracked-out all-caps labels), one monospace reserved specifically for data readouts (serial numbers, the countdown timer, timestamps in the event log) since that's earned by actual data, not applied as decoration to every small label.
- **Layout:** one screen, no scrolling required for the main view. 3 to 4 listener panels in a horizontal row, each showing service name, a large countdown (seconds until rotation), truncated serial, and current status. Below that, a single scrolling event log, terminal-style, one line per detect/issue/swap event, newest at the bottom with auto-scroll. Two small text-style actions per panel, "expire" and "corrupt", not glossy buttons, this is a console, not a SaaS product.
- **Principles:** the only motion is a panel's border color shifting on an actual status change and the countdown ticking down, both driven by real state, nothing decorative or hover-triggered. Avoid rounded-card-plus-soft-shadow styling on every panel, that's the generic default for this kind of layout and doesn't fit an ops-console feel.

**Component shape:** `<Dashboard>` holds the polling state, `<ListenerPanel>` renders one card (name, countdown, serial, status, two actions), `<EventLog>` renders the scrolling feed. Plain `useState`/`useEffect` polling is enough at this scale, no state management library needed.

During development, run the Vite dev server (`npm run dev` in `ui/`) with API calls proxied to `localhost:8080`. For what reviewers actually see, build once (`npm run build`) and commit the output, a pragmatic call for a demo repo, not a general practice.

## 6. Data Model

```sql
CREATE TABLE certs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name TEXT NOT NULL,
    common_name TEXT NOT NULL,
    serial_number NUMERIC(39,0) NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
        -- ACTIVE, EXPIRING, CORRUPTED, ROTATING, FAILED
    cert_pem TEXT NOT NULL,
    cert_path TEXT NOT NULL,
    key_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_certs_service_active
    ON certs(service_name)
    WHERE status = 'ACTIVE';
```

Only one `ACTIVE` cert per `service_name` at a time, enforced at the database level, not just in application logic.

```sql
CREATE TABLE cert_events (
    id BIGSERIAL PRIMARY KEY,
    service_name TEXT NOT NULL,
    event_type TEXT NOT NULL,   -- DETECTED_EXPIRING, DETECTED_CORRUPTED, ISSUING, SWAPPED, FAILED
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Written by the watcher and remediator at each step of the loop. This is what the dashboard's event log reads from, it exists to make the backend's behavior visible, not as a durable audit trail.

## 7. Internal API Surface

Not public-facing, just enough for the watcher/remediator internals and for a reviewer to poke at the system directly.

| Method | Path | Purpose |
|---|---|---|
| GET | `/internal/certs` | List full inventory |
| GET | `/internal/certs/{serviceName}` | Single cert record |
| POST | `/internal/certs/{serviceName}/rotate` | Manually trigger issuance + hot-swap |
| POST | `/internal/failures/{serviceName}?type=EXPIRE\|CORRUPT` | Inject a failure |
| GET | `/internal/events` | Last 50 events, newest last, for the dashboard's log feed |
| GET | `/dashboard` | The static dashboard page itself |

## 8. Configuration

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/pki
    username: pki
    password: pki
  ssl:
    bundle:
      pem:
        demo-a:
          reload-on-update: true
          keystore:
            certificate: file:./runtime/demo-a/cert.pem
            private-key: file:./runtime/demo-a/key.pem
        demo-b:
          reload-on-update: true
          keystore:
            certificate: file:./runtime/demo-b/cert.pem
            private-key: file:./runtime/demo-b/key.pem
        # demo-c, demo-d follow the same pattern

aws:
  kms:
    endpoint: http://localhost:4566
    region: us-east-1
    ca-key-id: # set after running scripts/create-ca-key.sh

pki:
  cert-validity: PT2M
  rotate-threshold: PT30S
  watcher-interval: PT5S
```

## 9. Package Layout

```
cert-reflex/
├── docker-compose.yml
├── scripts/
│   ├── create-ca-key.sh
│   └── inject-failure.sh
├── runtime/                        # cert/key files the SSL bundles watch, gitignored
├── ui/                              # React SPA (Vite), source only
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       └── components/
│           ├── ListenerPanel.jsx
│           └── EventLog.jsx
├── src/main/java/dev/<you>/certreflex/
│   ├── issuer/
│   │   ├── CertificateIssuer.java
│   │   ├── KmsContentSigner.java
│   │   └── CertificateBuilder.java
│   ├── inventory/
│   │   ├── CertRecord.java
│   │   ├── CertRepository.java
│   │   └── CertStatus.java
│   ├── watcher/
│   │   └── CertWatcherJob.java
│   ├── remediator/
│   │   └── CertRemediator.java
│   ├── demo/
│   │   ├── DemoListenersConfig.java   # extra Tomcat connectors
│   │   └── DemoController.java
│   ├── events/
│   │   ├── CertEvent.java
│   │   ├── CertEventRepository.java
│   │   └── CertEventRecorder.java
│   ├── admin/
│   │   └── AdminController.java       # list / rotate / inject-failure / events
│   └── CertReflexApplication.java
├── src/main/resources/static/dashboard/
│   └── ...                            # committed build output of ui/, so `docker compose up` stays one command
└── src/test/java/dev/<you>/certreflex/
    └── issuer/CertificateIssuerIT.java   # Testcontainers
```

## 10. Cert State Machine

```
ACTIVE ──(nearing expiry)──▶ EXPIRING ──▶ ROTATING ──▶ ACTIVE (new serial)
ACTIVE ──(parse/hash fail)─▶ CORRUPTED ──▶ ROTATING ──▶ ACTIVE (new serial)
ROTATING ──(issuance or swap error)──▶ FAILED   (logged, not auto-retried in this scope)
```

## 11. Design Decisions Already Made

- **Key custody model:** the CA private key never leaves KMS (or LocalStack's emulation of it). The issuer sends a digest, gets back a signature. No CA private key material ever sits in application memory. Leaf private keys, by contrast, are generated locally, since the process needs them to terminate TLS, only the CA key is protected.
- **Concurrency safety:** ShedLock on the watcher job.
- **Zero-downtime swap:** Spring Boot 3.2+'s SSL bundle `reload-on-update`, confirmed shipped as "Implement SSL bundle reload" in the 3.2.0 release line. The demo should prove this concretely (same curl connection, before/after cert diff), not just assert it.
- **Docker Compose for the whole stack:** Postgres and LocalStack both run in compose, one command gets a reviewer to a working demo.
- **Cert validity window:** 2 minutes, rotation triggers under 30 seconds remaining. Full detect-and-heal cycle visible in under a minute during a live walkthrough.
- **Key algorithm:** ECDSA P-256 for the CA's signing key.
- **Demo listener structure:** one process, 3 to 4 embedded Tomcat connectors on different ports, each with its own SSL bundle.
- **Failure modes simulated:** both expiry and corruption, via an admin endpoint and a thin shell wrapper around it.
- **Repo framing:** README stays neutral, no mention of the company this was built for or why. That context lives in outreach and conversation, not in the repo.
- **Testing depth:** Testcontainers integration tests cover the issuer only (Postgres + LocalStack containers). Watcher and remediator are exercised through the live demo run itself, not separate automated coverage.
- **UI approach:** a React SPA (Vite), not the plain static page originally planned. Justified because the goal shifted from "visible during a live walkthrough" to "something people can look at on their own", and a more polished, resume-consistent frontend (React is already on your skills list, and TalentCove already used it) earns its extra weekend hours under that goal.
- **Distribution, not hosting:** demoed locally and captured as a short recording for the README, not deployed publicly. An unauthenticated "corrupt this cert" control sitting on the open internet reads badly for any company, worse for a security one. This keeps the backend's scope unchanged, no auth layer needed, since only you are ever the one clicking it.
- **Built output committed to the repo:** `ui/`'s Vite build output is committed into the Spring Boot static resources rather than requiring a build step at clone time, so `docker compose up` stays a one-command reviewer experience without needing Node.js installed. A pragmatic call for a demo repo, not a general practice.
- **Event log table:** added specifically to back the dashboard's live feed, not intended as a durable audit trail. Cut along with the log panel if Sunday afternoon is tight.

## 12. Testing Strategy

`CertificateIssuerIT`, backed by Testcontainers, spins up Postgres and LocalStack in the test lifecycle:

1. Create the CA key in the LocalStack container via the AWS SDK (same call the setup script uses).
2. Issue a cert through the real issuer code path.
3. Assert the signature verifies against the CA's public key (fetched via KMS `GetPublicKey`).
4. Assert the cert parses cleanly and its validity window matches the configured `cert-validity`.
5. Assert the `SubjectAlternativeName` matches what was requested.

No mocking of KMS. The point of using LocalStack is to test against the real API shape.

## 13. Local Dev Environment

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: pki
      POSTGRES_USER: pki
      POSTGRES_PASSWORD: pki
    ports:
      - "5432:5432"

  localstack:
    image: localstack/localstack:latest
    ports:
      - "4566:4566"
    environment:
      - SERVICES=kms
```

```bash
# scripts/create-ca-key.sh
awslocal kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "self-healing PKI intermediate signing key"
# copy the returned KeyId into pki.aws.kms.ca-key-id
```

## 14. What a Reviewer Should See

1. Clone repo, `docker compose up`, `scripts/create-ca-key.sh`, app starts clean.
2. Open `http://localhost:8080/dashboard`, see all listener panels green and counting down.
3. Click "corrupt" on one panel, or `curl -X POST localhost:8080/internal/failures/demo-a?type=CORRUPT` for the same effect.
4. Watch the panel's border flip color and the event log scroll in real time: detected, issuing, swapped.
5. In a second terminal, `curl -k https://localhost:8444` before and after, same connection, different serial, no downtime in between, the dashboard is showing you the same thing the network is actually doing.
6. Click "expire" on another panel to show the second failure path.
7. Read the README's scope section, understand exactly what was built and why the rest was cut.
8. Record steps 2 through 6 as a short screen capture, 15 to 30 seconds. That recording is what actually goes in the README and gets linked in outreach, not a live link.
