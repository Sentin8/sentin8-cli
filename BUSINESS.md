# Sentin8:CLI - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Sentin8:CLI **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

`sentin8-cli` is the operator's **single entry point for platform
lifecycle**: it bootstraps a fresh database into a running platform
(roles, schemas, grants), enrolls every service and app at runtime
(composable registration), controls the fleet through Sentin8:Captain,
and answers operator questions (status, machines, autoscaler, secrets).
The business value it delivers:

- **One authority for bootstrap.** The platform database is initialized
  exactly once, from the repo that owns the SQL - never by a service at
  boot. The bootstrap window (pre-identity) is explicit and closed.
- **A signed-in operator, not shared credentials.** Device-flow sign-in
  gives every operator a personal identity; every post-bootstrap action
  is authorized as that identity - no shared admin passwords.
- **Composable enrollment.** Every service repo self-describes its
  registration surface; the CLI merges any mix of repo directories into
  the same registry tables - verticals onboard without platform code
  changes.
- **Fleet control through the supervisor.** Start, stop, upgrade, place,
  status, and autoscaler approval all go through Sentin8:Captain - never
  process kills.

## 2. Business Scope (What the Service Provides)

| Area | Capabilities |
|---|---|
| Platform bootstrap (`db bootstrap`) | Platform SQL (roles, schemas, grants, RLS helpers, OAuth role seeding) applied ONCE; refuses on an initialized platform; also DB listing seeds |
| Vertical init (`vertical init`) | Per-vertical database + schemas + SQL + RLS from per-repo `sql/` directories |
| Vertical enrollment (`vertical enroll` / `unenroll`) | Composable per-repo registration: services, admin scopes, declarative policies, relations, **schedules**, M2M workload grants, error codes, consent providers, app store listings, captain catalog entries, Valkey ACL keys |
| Fleet control (`captain …`) | Fleet start/stop/restart; per-instance restart/stop/start/rolling-upgrade (multi-key parallel); status tables with version+build |
| **Fleet placement (`captain place`)** | Operator hand-placement of a service onto a named machine; the target's placement gate answers with a refusal reason on violation |
| Autoscaler operations (`captain autoscaler*`) | Machine provisioning state (profile, backend, fleet size, leader), pending provision/deprovision requests, approve/reject |
| Declarative service commands (`sentin8 <svc> …`) | Commands resolved from the registry - every enrolled service's command surface is call-table-driven, no CLI rebuild |
| Secrets (`secrets …`) | Secret-reference management (set/list/reveal by reference - values never in logs) |
| Operator identity (`auth`/sign-in) | Device-flow sign-in (PKCE), token persistence + refresh |

### What the CLI does NOT own (business boundary)

| Out of scope | Owner |
|---|---|
| Service business logic | each service (the CLI calls owner APIs) |
| Registry/policy table semantics | the owning services (the CLI writes rows, never re-defines them) |
| Process supervision | Sentin8:Captain (the CLI instructs, never kills) |
| Destructive resets | no shipped command - dev reset is the guarded repo script |
| Machine-provisioning internals | OpenTofu modules + provider credentials |

## 3. Business Capabilities

| Capability | Business rule |
|---|---|
| Two bootstrap states | The platform is either uninitialized (superuser DSN works) or initialized (every CLI action requires the signed-in operator); `db bootstrap` refuses to run twice - a reset is a development-only, guarded operation |
| Guarded dev reset (full-tree data) | The guarded repo script deletes EVERY database on the dev cluster (all verticals + platform) and brings back ONLY the core platform (bootstrap + platform enroll + platform-core-scoped boot); no vertical data is preserved and no vertical service is started - a vertical re-joins on its own group flow when the operator chooses |
| One-time initialization | Platform SQL is applied as one converged unit (idempotent DO-blocks) - a re-run after a database-only restore heals drift instead of failing the fleet |
| Composable enrollment | Each repo ships one `service-registration.json` + `catalog.json`; enroll merges fragments per vertical; re-running enroll converges to the same rows (idempotent) |
| Runtime command surfaces | Service subcommands live in the registry's call table - adding a command to a service needs no CLI release |
| Fleet status truth | Instance tables report version + build hash from the registry - an operator always sees WHICH binary is live |
| Placement-aware control | Restart/stop/upgrade/place all respect and surface placement rules; a refused placement states its reason |
| Approval-gated scaling | Machine provisioning executes only on an operator's approve (in the `manual` profile) or a deliberately configured backend/profile |
| Secret references | The CLI manages references - it never stores provider tokens, keys, or passwords in command history or logs |

## 4. Business Events (Outbound)

The CLI emits no events; it WRITES registry rows (which the owning
services surface as events) and calls APIs. Inbound: command responses,
SSE/HTTP status streams from captain (upgrade/startup/shutdown progress).

## 5. Business Rules & Invariants

1. **`db bootstrap` runs once**; every later action needs the signed-in
   operator.
2. **No destructive command ships** - recovery from a bad bootstrap is
   the guarded dev script, never a CLI path.
3. **Every enrollment upsert is idempotent** - re-running enroll is the
   repair path, not an error.
4. **The CLI links no service binary** - service surfaces are pulled
   from registration output (starters never link services).
5. **Operator identity is personal** (device flow); shared credentials
   exist only in the pre-identity bootstrap window.
6. **Fleet mutations route through captain** - never direct process
   manipulation.
7. **Secrets stay by-reference** - values never enter command output.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Sentin8:CLI |
|---|---|
| Platform operator (first boot) | `db bootstrap` → `vertical init` → `vertical enroll` → `captain start` |
| Platform operator (steady state) | `captain status`, rolling `upgrade-instance`, autoscaler approval, `captain place` |
| Vertical engineers | Enroll their service repo; init its database; iterate without platform changes |
| Dev/test operators | `make fleet-up` paths in the group Makefiles drive this CLI |
| Support/diagnosis | Read fleet tables, machine summaries, pending queues |

## 7. KPIs / Success Criteria

- **Time-to-platform**: a fresh environment reaches a signed-in operator
  with an enrolled fleet in one guided command chain.
- **Zero ambiguity**: every CLI action either converges idempotently or
  fails with the authoritative reason - no half-applied states.
- **No credential leakage**: no secret appears in output, history, or
  logs.
- **Operational safety**: all destructive intent is unexpressible in the
  shipped tool; all fleet mutations traverse the supervisor.

## 8. Dependencies & Reliance on Other Services

| The business relies on… | For |
|---|---|
| PostgreSQL (superuser DSN) | The pre-identity bootstrap window; vertical `init` |
| Sentin8:Auth | Device-flow operator identity; M2M token minting for API calls |
| Sentin8:Captain | Fleet control + status surfaces (UDS/HTTP) |
| Owner services' APIs | Enrollment targets (`vertical enroll` upserts) and registry-declared commands |
| The SDK plane | Shared config/registration types - linked, never service binaries |

## 9. Acceptance Criteria

1. A fresh database: `db bootstrap` initializes platform + roles; running
   it again is refused with a clear message.
2. `vertical enroll <repo>` for a new service adds its registry rows,
   schedules, catalog entry, and Valkey keys; running it twice changes
   nothing.
3. `captain start` brings the fleet Active (health-gated tiers);
   `captain status` shows version + build per instance.
4. `captain upgrade-instance KEY` performs a zero-downtime swap and
   reports phase progress.
5. `captain place --ip=<machine> <svc>` places the service on that
   machine, or reports the placement-gate refusal verbatim.
6. Registry-declared service subcommands work without a CLI rebuild.
7. All identity-requiring commands fail closed without a signed-in
   operator.

## 10. Open Business Questions

- Packaged-install (deb) enrollment flows land with the packaged-install rollout.
- Remote-machine enrollment convenience (drive a fresh machine's enroll
  from anywhere) may follow the fleet E2E story .

---

**Architecture & Design:** sentin8:cli and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
