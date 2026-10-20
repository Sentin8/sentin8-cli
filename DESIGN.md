# Sentin8:CLI - Detailed Design Document

> Wire-level construction of `sentin8-cli`. The overview lives in
> `README.md`; the operator capability list in `BUSINESS.md`.

## 1. Scope & Context

The CLI is the **bootstrap + enrollment + control** starter. It links
ONLY the SDK plane (invariant RS-2 - starters never link services) and
executes two kinds of authority:

- **Database-plane authority** (pre-identity): `db bootstrap` and
  `vertical init` run SQL directly as the DDL superuser - the only
  credential available before Sentin8:Auth exists. `db bootstrap` is the
  ONLY command that applies platform SQL; it refuses when the
  `sys.platform_bootstrap` scout exists (BOOTSTRAP-1: the database has
  exactly two states).
- **Identity-plane authority** (post-identity): every other command
  (enroll, captain control, secrets, service commands) requires a
  signed-in operator (device-flow bearer) and calls owner APIs / the
  captain API - never direct SQL.

```mermaid
graph TD
    OP["Operator"] --> CLI["sentin8-cli"]
    CLI -- "device flow (PKCE)" --> AUTH["Sentin8:Auth"]
    CLI -- "sqlx direct (pre-identity only)" --> PG[("Platform DB")]
    CLI -- "sqlx direct (init: per-vertical SQL)" --> VDB[("Vertical DBs")]
    CLI -- "M2M/bearer (enroll, commands)" --> OWNERS["Owner services"]
    CLI -- "HTTP/UDS" --> CAPT["Sentin8:Captain"]
    REG["--print-registration JSON<br/>(per-repo service-registration.json)"] --> CLI
```

## 2. Runtime Architecture

| Module | Role |
|---|---|
| `main.rs` / `lib.rs` | Command tree (clap); boot-time helpers. |
| `auth.rs` | Device-flow operator sign-in (PKCE, token persistence + refresh); `get_valid_token_blocking`. |
| `db.rs` | `db bootstrap` (`migrations/platform.sql` + `public_helpers.sql`, scout-gated), `db migrate` (`--sql-dir` service SQL), `db seed-listings`. |
| `vertical_registry.rs` | Composable enrollment: read `--print-registration --section=…` JSON from each repo, merge fragments per vertical, upsert registry tables (`sentin8_vertical_services`, admin scopes, policies, relations, **schedules** (SDD §2.4), error codes, consent providers, app store listings, captain catalog entries, Valkey keys) - idempotent. |
| `captain.rs` | Fleet control: start/stop/restart, per-instance restart/stop/start/upgrade (+ UDS transport), status tables, autoscaler view + approve/reject, **`captain place`** (FLEET-4 hand placement). |
| `transport.rs` | Captain transport resolution: local UDS (`SO_PEERCRED`) when on the same machine; HTTP for remote hosts. |
| `commands.rs` | Declarative service commands - subcommands resolved from the registry (`service_commands` table), no hardcoded per-service command list. |
| `secrets.rs`, `func.rs`, `infra.rs` | Secret-reference management, func tooling, infra helpers. |
| `infra.rs` (status probe) | Direct PostgreSQL + Valkey probes behind `captain services`' instance table (never through captain - see §5). PostgreSQL renders version/connection-census/db-size from `pg_stat_activity`; Valkey renders version/clients/memory/keys/uptime parsed from the `INFO` reply. The Valkey decode is RESP3-aware: GLIDE negotiates RESP3 by default and `INFO` replies as a `VerbatimString` - the parser accepts `VerbatimString`/`BulkString`/`SimpleString` and treats ANY other reply shape as a probe error (a visible `unreachable (…)` line), never a silent empty summary. Both probes carry a 3s timeout and degrade to a one-line `unreachable (reason)` - `make status` never aborts on a down backend; connection URLs render with passwords masked. |
| `call.rs` | Generic authenticated HTTP call plumbing. |

## 3. Data Model - what the CLI writes

The CLI owns **no tables of its own**; it is the provisioning WRITER for:

| Target | Written by | Idempotency |
|---|---|---|
| `sys.platform_bootstrap` | `db bootstrap` (scout - written ONCE) | refuses re-run |
| Platform roles/schemas/grants | `platform.sql` (bootstrap, DO-block guarded) | converges (re-run safe) |
| Vertical databases + schemas + RLS | `vertical init` from per-repo `sql/` | converge-on-apply |
| `sentin8_vertical_services` + friends | `vertical enroll` | upsert per (vertical, service) |
| `cron.schedules` | `vertical enroll --section=schedules` | upsert idempotent (SDD §2.4) |
| Valkey `captain:*` catalog keys | `vertical enroll` | upsert |
| Operator device tokens | local credential store (user-scoped) | rotate on refresh |

## 4. API/Command Surface

```mermaid
graph LR
    subgraph PRE["Pre-identity (superuser DSN)"]
        BOOT["db bootstrap"]
        INIT["vertical init"]
    end
    subgraph POST["Signed-in (device flow)"]
        ENROLL["vertical enroll / unenroll"]
        CAPT["captain …(status/control/place)"]
        SVC["<service> … (registry-declared)"]
        SEC["secrets …"]
    end
    OP["operator"] --> PRE & POST
    PRE -->|"direct SQL"| PG[("PostgreSQL")]
    POST -->|"bearer/M2M"| API["owner APIs + captain"]
```

Command families (see `README.md` §4): `db`, `vertical`, `captain`,
per-service registry-declared commands, `secrets`.

## 5. Cross-Cutting Concerns

- **Auth states**: BOOTSTRAP-1's two-state contract - pre-identity
  commands work only with the DDL superuser; post-identity, every CLI
  action requires the signed-in operator. `db bootstrap` refuses to run
  on an initialized platform (the scout + table-presence guard also
  catches half-finished bootstraps).
- **SQL loading**: platform SQL is embedded (`include_str!`); service SQL
  is runtime-loaded from `--sql-dir` paths (the CLI binary stays
  decoupled from any service's schema).
- **Registration consumption**: the CLI never hardcodes a service's
  surface - every service self-describes via `--print-registration`
  sections (`service`, `admin_scopes`, `policies`, `relations`,
  `m2m_grants`, `schedules`, `admin_ui`, `error_codes`, `consent`,
  `pg_roles`, `commands`).
- **Captain control channel**: UDS with kernel-proven `SO_PEERCRED` for
  same-machine control; Shield-gated HTTP for remote; `captain place`
  builds a per-machine HTTP call (FLEET-4).
- **Secrets posture**: the CLI never stores DSNs or secrets it provisions
  - they live in the operator env (`.env`) and flow via `database_env_vars`
  declarations at spawn; the device-flow token store is user-scoped.
- **Operator env loading**: every CLI subcommand loads the tree-root
  operator `.env` via `dotenvy::dotenv()` - and `scripts/dev-destroy.sh`
  (the destructive local reset, DEVRESET-1) sources the SAME file
  explicitly before its first step, refusing loudly when absent: the
  script's maintenance connection (certificate identity, `postgres-ops`
  pair) and its `captain stop` precondition must behave identically from
  a fresh shell and an operator session, and a half-destroyed workspace
  (fleet stopped, databases untouched) must never result from a missing
  environment.
- **The dev reset drops ALL data but re-initializes ONLY the platform core
  (DEVRESET-2, boot scope from STARTSCOPE-1 / RS §4.5.2)**:
  `dev-destroy.sh` is a FULL-TREE data reset - every non-template database
  on the dev cluster is dropped: vertical databases (`bank8`, `hotel8`, …)
  first, enumerated vertically-agnostically from `pg_database` (the script
  never names a vertical, AGENTS rule 1), then the `sentin8` platform
  database is dropped and recreated. The platform database carries the
  registry tables, so the reset also un-enrolls every vertical by
  construction. Vertical `_service` ROLES survive on the cluster (they are
  passwordless certificate-identity rows; the vertical's own
  `vertical init`/`vertical enroll` converges them idempotently), while
  the `sentin8_*_service` platform roles are dropped for re-seeding.
  Re-initialization covers the CORE PLATFORM ONLY: `db bootstrap`, the
  platform-fragment enrollment, and the post-bootstrap `captain start` —
  which runs under the platform-core `SENTIN8_SERVICES` pin (spawning a
  vertical service against its dropped database would crash-loop it). A
  vertical re-joins the fresh platform via its own group
  `vertical init && make enroll && make start` at the operator's choice;
  the dropped vertical state is disposable by design (greenfield data).
- **Infra probes bypass captain by design** (`infra.rs`): captain owns
  the Valkey service registry and intentionally has no PostgreSQL
  dependency - it must boot and report status even when PostgreSQL is
  down. The CLI probes the backends directly over the operator env
  (`DATABASE_URL` / `VALKEY_URL`), so a saturated or unreachable backend
  surfaces as a readable `unreachable (…)` line inside the status table
  instead of breaking the supervisor or hiding the problem (early
  signal for pool exhaustion). The Valkey probe connects through the
  shared certificate-identity GLIDE factory with the read-only control
  identity; the RESP3 `INFO` decode contract is in §2.

## 6. Failure Modes & Recovery

| Failure | Behavior |
|---|---|
| `db bootstrap` on an initialized platform | Refuse (scout exists) - never a second window |
| Half-finished bootstrap (tables present, scout absent) | Treated as initialized; recovery = repo `dev-destroy.sh` (dev-guarded), never a destructive CLI command |
| Enroll against an unreachable Auth/DB | Clear error; upserts are idempotent - re-run converges |
| Captain unreachable over UDS | Transport falls back / errors distinctly (401/403 surface as auth, not transport) |
| Device token expired | Refresh; on refresh failure, re-run device flow |

## 7. Concurrency & Performance Model

Single-process, request-scoped - no daemons. sqlx pools created per
command run; enrollment merges fragments in memory before upserting
(one connection per target database).

## 8. Invariants

1. `db bootstrap` is the only platform-SQL applier and refuses
   re-initialization.
2. No destructive command exists in the shipped CLI (dev reset is the
   guarded repo script).
3. Starters link no service binary (RS-2); every service surface is
   registry-declared.
4. All enrollment upserts are idempotent - convergence on re-run.
5. The operator token never leaves the local store; secrets flow
   by-reference.

## 9. Testing Strategy

- Unit: enrollment fragment merging, schedule upsert SQL shapes,
  transport resolution, bootstrap scout logic.
- Integration (DB/Valkey-gated): bootstrap convergence on a fresh
  database; enroll upsert idempotency (run twice → same rows).
- Deliberately NOT tested here: cloud provisioning modules, real device
  flows.

## 10. Open Questions

- Packaged-install enrollment (the vendored-registry path) tracks with
  the packaging backlog (SD-7).
- A `captain enroll-remote` convenience (drive a fresh machine's enroll
  from the CLI) may follow the FLEET E2E story.

---

**Design attribution:** sentin8:cli and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
