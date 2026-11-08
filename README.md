# Vapor Build Cache Server

Vapor Build Cache owns signed Cargo target-directory snapshots used to restore
a developer workspace. It is not a shared compiler-invocation cache such as
`sccache`, and it does not run or provision native builders. It never stores
source checkouts, secrets, Loo Cast files, or Mad Max game content. Platform
composes its API and admin router and owns build-operation orchestration;
Artifact Server remains responsible for Vapor application release archives.

The first supported targets are `x86_64-unknown-linux-gnu` and
`x86_64-pc-windows-gnullvm`. A snapshot is served only when the requested client
version, `Vapor.lock` hash, and toolchain-lock hash exactly match the current
server configuration. Older clients cannot select historical generations.

## Routes

When composed, public routes live under `/api/build-cache/`:

- `GET /v1/status` reports target configuration and whether a current snapshot
  exists, without exposing server paths or credentials.
- `GET /v1/targets/{target}/current/manifest.json` and `.sig` serve current
  signed metadata after exact client/lock checks.
- `GET /v1/targets/{target}/current/snapshot.tar.zst` streams the matching
  archive after the same checks.
- `GET /admin/build-cache` is a root-authorized read-only target inventory.
- Internal operation and candidate routes are blocked by both Caddy templates
  and also require the private VPS orchestrator token when reached over the
  loopback interface.

The internal orchestrator API issues a short-lived, one-use ticket for one
supported target and caller-supplied operation ID. The ticket is in memory and
is lost on service restart; it is upload authorization, not a durable build-job
record. Candidate uploads carry a signed manifest and stream the archive to
staging. The service verifies the current lock/environment
identity, Ed25519 signature, exact archive size and SHA-256 before atomically
switching the target's current pointer. The atomic pointer includes the
operation ID and promotion time, so the admin inventory can identify the last
successful promotion without a separate, potentially inconsistent audit file.
It does not preserve prior snapshot generations or failed candidate/job history.
A rejected candidate leaves the prior pointer unchanged.

## Configuration

`VAPOR_BUILD_CACHE_ROOT` defaults to `/var/lib/vapor-server/build-cache`;
`VAPOR_BUILD_CACHE_BIND` defaults to `127.0.0.1:7117`. Exact rolling identities
and trusted snapshot public-key details are read from the `VAPOR_BUILD_CACHE_*`
environment values. Missing lock or signing configuration keeps the service
healthy but reports snapshots unavailable; it never falls back to a local
client build.

The separate Build Cache signing private key belongs only in protected VPS
configuration and is not read by this service. Builder VMs receive no signing
key. The current service API has no browser upload, user-selected generation,
or snapshot deletion route.
