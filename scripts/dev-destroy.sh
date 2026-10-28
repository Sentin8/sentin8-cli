#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
# SPDX-License-Identifier: Apache-2.0
#
# dev-destroy.sh - LOCAL DEVELOPMENT reset (BOOTSTRAP-1, DEVRESET-2).
#
# Destroys ALL platform and VERTICAL data and re-bootstraps the platform
# from an empty database: every non-template database on the dev cluster
# is dropped (vertical-agnostic enumeration - the script never names a
# vertical), and ONLY the core platform services are re-initialized and
# started (platform-core boot pin). A vertical re-joins a fresh platform
# via its own group tooling (`make enroll && make start`);
# `vertical init` recreates its database/schema from its own fragments.
# NEVER shipped or packaged - a deployment that only receives binaries
# cannot reach this. The SENTIN8_DEV=1 guard makes accidental production
# use impossible: the variable must be set explicitly in the invoking
# environment, and the CLI itself has no destructive path at all.
#
# Usage (from the sentin8-cli repo):
#   SENTIN8_DEV=1 scripts/dev-destroy.sh [--note "why"]
#
# Split-layout contract (RS §4.4): the CLI repo owns this script; binaries
# live per-repo under {group}/{repo}/target/{debug,release}. The binary
# prefix is composed across ALL built repos so `--print-registration`
# probes and `captain start` resolve the same binaries the fleet runs.
# Enrollment is COMPOSABLE (RS §6): every service repo's
# service-registration.json fragment is passed explicitly - no aggregate
# registry file exists in this layout.
#
# DB credentials come from .env's DATABASE_URL (never interactive - a prompt
# here is what hung the first run; parse user/password out of the URL).
#
# Steps: stop services → drop ALL databases (verticals + platform) →
# reset platform cluster roles → `sentin8-cli db bootstrap` (scout-gated) →
# enroll (platform fragments only) → scoped start (platform core) → finalize.
set -euo pipefail

if [[ "${SENTIN8_DEV:-}" != "1" ]]; then
    echo "ERROR: destructive reset requires SENTIN8_DEV=1." >&2
    echo "This script is for LOCAL DEVELOPMENT ONLY and is never shipped." >&2
    exit 1
fi

# The CLI repo is this script's owner. Layout (RS §4.4):
#   {tree}/sentin8/sentin8-cli/scripts/dev-destroy.sh
# so the TREE ROOT is TWO levels above the CLI repo (the group folder sits
# between), and the operator .env lives there.
CLI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TREE_ROOT="$(cd "$CLI_ROOT/../.." && pwd)"
cd "$CLI_ROOT"

# Load the operator environment BEFORE anything else (DEVRESET-1): the
# maintenance connection derives its user from DATABASE_URL and the stop
# phase must not leave a half-destroyed workspace when the shell is fresh.
# Every CLI subcommand honors the same file through dotenvy::dotenv() -
# this makes the script behave identically from `bash scripts/…` and an
# operator session. Refuse loudly when the file is missing (the TLS
# material paths and DSNs have nowhere else to come from).
OPERATOR_ENV="$TREE_ROOT/.env"
if [[ ! -f "$OPERATOR_ENV" ]]; then
    echo "ERROR: operator .env not found at $OPERATOR_ENV." >&2
    echo "It carries DATABASE_URL and the SENTIN8_* paths the reset needs." >&2
    exit 1
fi
set -a
# shellcheck disable=SC1090
source "$OPERATOR_ENV"
set +a

NOTE="${2:-dev reset $(date -u +%FT%TZ)}"

# Compose the binary prefix across every built repo (debug preferred, the
# fleet's debug convention): platform services + starters + verticals.
compose_prefix() {
    local profile="release"
    [[ -d "$CLI_ROOT/target/debug" ]] && profile="debug"
    local prefix=""
    local d
    for d in "$TREE_ROOT"/*/*/; do
        if [ -d "$d/target/$profile" ]; then
            prefix="${prefix}${d}target/${profile}:"
        fi
    done
    # Trim the trailing colon.
    echo "${prefix%:}"
}
CAP_PREFIX="$(compose_prefix)"
export SENTIN8_CAPTAIN_BINARY_PREFIX="$CAP_PREFIX"

CLI="$CLI_ROOT/target/debug/sentin8-cli"
[[ -x "$CLI" ]] || CLI="$CLI_ROOT/target/release/sentin8-cli"

echo "[dev-destroy] force-recreating infra containers (WARM-1) ..."
# The reset recreates the whole .run/secrets tree (infra TLS material,
# CAs), and Docker Desktop/WSL bind-mount hashes freeze at container
# creation time: a container whose bind-mount source was replaced
# underneath it sees empty/stale mounts until recreated (observed:
# postgres initdb EPERM crash-loop 2026-10-26; valkey 'unhealthy' probe
# streak with an empty /tls 2026-10-27). Recreate BOTH containers via the
# group's compose project - never a per-container patch, never from a
# service process (CLI DESIGN §5 dev-reset bullet).
docker compose -f "$TREE_ROOT/sentin8/docker-compose.yml" up -d --force-recreate >/dev/null 2>&1 \
    || echo "WARN: infra force-recreate failed - run 'make infra-up' manually if the fleet cannot reach PG/Valkey."

echo "[dev-destroy] stopping platform ..."
STOP_OUT="$($CLI captain stop 2>&1 || true)"
echo "$STOP_OUT"
# Success = either an explicit "captain is not running" (nothing was up)
# or the graceful-shutdown acknowledgement ("captain stopped." printed
# after "Shutdown request accepted."). Anything else means the operator
# must sign in first - the drop step must never run while captain is up.
if ! echo "$STOP_OUT" | grep -q 'captain is not running' \
   && ! echo "$STOP_OUT" | grep -q 'captain stopped'; then
    echo "ERROR: could not stop the platform." >&2
    echo "Once bootstrapped, 'captain stop' requires a signed-in operator" >&2
    echo "with 'sentin8:captain:admin'. Run: $CLI signin" >&2
    echo "(approve the device flow in the browser), then re-run this script." >&2
    exit 1
fi

echo "[dev-destroy] dropping databases (DBX: database per vertical) ..."
# Certificate identity (group DESIGN.md §3.2): the maintenance connection
# presents the `postgres-ops` infra pair over TLS (verify-full) - there is
# no password to parse or export. Material comes from `make infra-tls`
# (the same mint that provisions the server leaf the client verifies
# against). psql takes TLS material as CONNECTION-STRING keywords, not
# trailing arguments - everything rides in the -d connstring.
SECRETS_DIR="${SENTIN8_SECRETS_DIR:-$TREE_ROOT/.run/secrets}"
DB_USER="${DATABASE_URL#postgres://}"; DB_USER="${DB_USER%%@*}"
[[ "$DB_USER" == *:* ]] && DB_USER="${DB_USER%%:*}"
DB_USER="${DB_USER:-sentin8}"
PSQL_CONN="host=localhost dbname=postgres user=$DB_USER sslmode=verify-full sslrootcert=$SECRETS_DIR/acme-ca/root-ca.crt sslcert=$SECRETS_DIR/infra-tls/postgres-ops.crt sslkey=$SECRETS_DIR/infra-tls/postgres-ops.key"
# Function form (NOT a string variable): a string would re-split the
# connstring's keywords and mangle them (the "invalid connection option"
# class); the function receives each argument intact.
mpsql() { psql -v ON_ERROR_STOP=0 -q -P pager=off -d "$PSQL_CONN" "$@"; }
# DBX (§6.6, DEVRESET-2): drop EVERY non-template database - the reset is a
# FULL-TREE data reset. Vertical-agnostic: enumerate databases from
# pg_database instead of a hardcoded vertical list (any enrolled workspace
# is covered; the core script never names a vertical, AGENTS rule 1).
# Platform LAST - the platform database is the drop that also un-enrolls
# every vertical (their registry rows live in db sentin8) and carries the
# fresh bootstrap. Vertical "_service" ROLES survive on the cluster:
# passwordless certificate-identity rows that `vertical init/enroll`
# converges idempotently (IF NOT FOUND / ELSE ALTER) - dropping them buys
# nothing; only the PLATFORM role reset below re-seeds anything.
mpsql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname NOT IN ('postgres','template0','template1');"
# NOTE: collect the list into a variable FIRST - piping psql through
# `grep -v` under `set -euo pipefail` silently KILLS the script when the
# filter empties it (only db sentin8 exists → grep exits 1 → pipefail
# abort before any DROP ran - the "returns fine but drops nothing" run).
# `|| true` keeps the empty list legal.
DB_LIST="$(mpsql -t -A -c "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres';" | grep -v '^sentin8$' || true)"
while read -r DB; do
    [[ -z "$DB" ]] && continue
    mpsql -c "DROP DATABASE IF EXISTS \"$DB\";"
done <<< "$DB_LIST"
mpsql -c "DROP DATABASE IF EXISTS sentin8;"
mpsql -c "CREATE DATABASE sentin8;"

echo "[dev-destroy] resetting per-service cluster roles ..."
# Cluster roles are NOT database-scoped: they survive the DROP DATABASE
# above with whatever configuration they carried from earlier conventions,
# and platform.sql's IF NOT FOUND role seed would then keep the stale
# state. Drop every PLATFORM per-service role so bootstrap recreates them
# from CURRENT seeds (passwordless - the `pgm` identity rows are re-written
# by the same bootstrap, group DESIGN.md §3.2). DEVRESET-2: vertical
# roles (`bank8_*_service`, `hotel8_*_service`, …) are NOT platform-owned
# state - they live across the reset and their vertical's own
# `vertical init/enroll` converges them (the `sentin8\_%` pattern already
# excludes them - this note makes the contract explicit).
TMPDIR_CLI="$TREE_ROOT/.tmp"
mkdir -p "$TMPDIR_CLI"
mpsql -t -A -c "SELECT rolname FROM pg_roles WHERE rolname LIKE 'sentin8\_%\_service' AND rolname NOT IN ('sentin8_db_service');" > "$TMPDIR_CLI/sentin8-roles.$$"
while read -r ROLE; do
    [[ -z "$ROLE" ]] && continue
    mpsql -c "DROP OWNED BY \"$ROLE\";"
    mpsql -c "DROP ROLE IF EXISTS \"$ROLE\";"
done < "$TMPDIR_CLI/sentin8-roles.$$"
rm -f "$TMPDIR_CLI/sentin8-roles.$$"
mpsql -c "DROP ROLE IF EXISTS sentin8_app_dev;"
mpsql -c "DROP ROLE IF EXISTS sentin8_app;"

echo "[dev-destroy] bootstrapping fresh platform ..."
# Use the PREBUILT CLI binary, not `cargo run`: a cargo run inside the
# bootstrap recompiles with sqlx::query! macros, whose compile-time checks
# need a LIVE seeded database - but the databases were just dropped and are
# not seeded until this bootstrap completes (incident 2026-09-22: `function
# sentin8_boot_policy_load does not exist` at the policy crate's macro
# expansion, aborting the re-roll). The caller is expected to have built
# first; the binary check makes that contract explicit.
if [[ ! -x "$CLI" ]]; then
    echo "ERROR: $CLI not found - build the CLI repo first (make build in the sentin8/ group)." >&2
    exit 1
fi
CLI_BIN="$CLI"
"$CLI_BIN" db bootstrap --operator-note "$NOTE"

echo "[dev-destroy] enrolling platform services (composable fragments, RS §6) ..."
# Every platform service repo carries its own registration fragment.
# Verticals are NOT enrolled here - their databases are created by
# `sentin8-cli vertical init/enroll` per group (see each group's Makefile).
# ORDER = the original registry's dependency order (app BEFORE sys: sys's
# dash seed reads app.store_listings; enrollment order is not dependency
# order in general - this is the proven sequence). dash is an APP repo -
# its fragment carries the inline app listing (slug/web_dir/listing, the
# WARN-11 form) that seeds app.store_listings + the captain:app_dir:dash
# key the proxy resolves; omitting it strands the dash hostname at the
# ingress ("no app found for hostname dash.ops.sys.…" - the 2026-10-05
# dev-destroy break). captain MUST be enrolled too (WARN-2 regression in
# this script's list): its m2m_grants self-declaration provisions the
# captain-* grant rows - without them the fleet's 401/heal loop for
# sentin8:captain-policy runs forever after every reset. sign MUST be
# enrolled too (SIGNENROLL-1): its pg_roles self-declaration provisions
# the sentin8_sign_service role + the m2m-sentin8:sign pgm identity row -
# without it every cert-auth connection from sentin8:sign fails
# ("certificate authentication failed" crash-loop 2026-10-27/28) and the
# type never reaches Active (the group Makefile already boots it - the
# missing enroll half).
PLATFORM_SERVICES="captain auth db storage app func cron flow bus stat post ai secrets sign bff proxy web sys acme dash"
ENROLL_PATHS=""
for s in $PLATFORM_SERVICES; do
    ENROLL_PATHS="$ENROLL_PATHS $TREE_ROOT/sentin8/sentin8-$s"
done
"$CLI_BIN" vertical enroll $ENROLL_PATHS

# Start BEFORE finalize: the lifecycle gate keys on finalized_at, so the
# bootstrap/enroll window (no Auth → nobody can sign in) still allows a
# local `captain start`. Finalize right after, marking the window closed -
# from that point on every lifecycle command requires a signed-in operator.
#
# STARTSCOPE-1 (RS §4.5.2): the boot is PLATFORM-CORE-scoped - with every
# vertical database dropped by DEVRESET-2 above, spawning a vertical
# service would crash-loop it. The pin scopes the spawn to the platform
# core (captain boots-skips its own entry); the catalog stays the full
# union (the pin filters only the boot spawn), so a vertical joins the
# fresh platform the moment its own group `make init && make enroll &&
# make start` runs.
echo "[dev-destroy] starting platform (bootstrap window - no sign-in needed yet) ..."
PLATFORM_CORE_SCOPE="sentin8:captain,sentin8:acme,sentin8:auth,sentin8:sys,sentin8:bus,sentin8:proxy,sentin8:db,sentin8:storage,sentin8:post,sentin8:stat,sentin8:secrets,sentin8:func,sentin8:cron,sentin8:flow,sentin8:ai,sentin8:app,sentin8:bff,sentin8:web"
SENTIN8_SERVICES="$PLATFORM_CORE_SCOPE" SENTIN8_CAPTAIN_BINARY_PREFIX="$CAP_PREFIX" "$CLI_BIN" captain start

echo "[dev-destroy] finalizing (credential-free scout marker - a@m.n/pass stays valid) ..."
"$CLI_BIN" db finalize

echo "[dev-destroy] done - sign in with a@m.n / pass (change it via self-service)."