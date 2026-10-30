#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
# SPDX-License-Identifier: Apache-2.0
#
# dev-destroy.sh - LOCAL DEVELOPMENT infra reset (CLI DESIGN §4.9a).
#
# A PURE INFRASTRUCTURE reset: bring the infra down, remove the volumes,
# bring the infra up. NOTHING ELSE. The script owns exactly one plane -
# the containers/volumes/TLS material of the dev cluster - and leaves
# database convergence to the operator's normal flow, which bootstraps
# automatically (bootstrap-if-needed gate, CLI DESIGN §4.9a):
#
#   make stop                                   # (already stopped is fine)
#   SENTIN8_DEV=1 scripts/dev-destroy.sh        # this script - infra virgin
#   make enroll                                 # bootstrap-if-needed + enroll
#   make start                                  # provision-on-boot + fleet up
#
# After the volume wipe the cluster is VIRGIN: fresh initdb (role sentin8
# + db sentin8, zero service schemas) and a fresh Valkey data dir (zero
# ACL state). The infra-TLS pass re-mints/confirms the leaves, republishes
# the CA chain, and RESEEDS pg_hba.conf/pg_ident.conf (the enroll pass
# appends runtime rows on top). `make enroll` then runs `db bootstrap`
# automatically when the scout is absent and converges every platform
# fragment; `make start` re-runs the same convergence on cold boot
# (provision-on-boot, CLI DESIGN §4.5). Each step is individually
# re-runnable - a failure is retried by running the SAME command again,
# never by starting over.
#
# NEVER shipped or packaged - a deployment that only receives binaries
# cannot reach this. The SENTIN8_DEV=1 guard makes accidental production
# use impossible: the variable must be set explicitly in the invoking
# environment, and the CLI itself has no destructive path at all.
#
# Usage (from the sentin8-cli repo):
#   SENTIN8_DEV=1 scripts/dev-destroy.sh
#
# Split-layout contract (RS §4.4): the CLI repo owns this script. The
# script needs NO database credential at all - the stop step rides the
# CLI's operator token, and the wipe is `docker compose down -v` (the
# maintenance plane's certificate identity stays in .run/secrets, never
# in this script).
set -euo pipefail

if [[ "${SENTIN8_DEV:-}" != "1" ]]; then
    echo "ERROR: destructive reset requires SENTIN8_DEV=1." >&2
    echo "This script is for LOCAL DEVELOPMENT ONLY and is never shipped." >&2
    exit 1
fi

# The CLI repo is this script's owner. Layout (RS §4.4):
#   {tree}/sentin8/sentin8-cli/scripts/dev-destroy.sh
# so the TREE ROOT is TWO levels above the CLI repo (the group folder sits
# between), and the operator .env lives there. The GROUP root carries the
# tree's compose file (the infra the reset owns).
CLI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TREE_ROOT="$(cd "$CLI_ROOT/../.." && pwd)"
GROUP_ROOT="$(cd "$CLI_ROOT/.." && pwd)"
cd "$CLI_ROOT"

# Load the operator environment BEFORE anything else: the stop phase must
# not leave a half-destroyed workspace when the shell is fresh, and the
# infra-TLS pass reads the SENTIN8_* paths from it. Every CLI subcommand
# honors the same file through dotenvy::dotenv(). Refuse loudly when the
# file is missing (the TLS material paths have nowhere else to come from).
OPERATOR_ENV="$TREE_ROOT/.env"
if [[ ! -f "$OPERATOR_ENV" ]]; then
    echo "ERROR: operator .env not found at $OPERATOR_ENV." >&2
    echo "It carries the SENTIN8_* paths the reset needs." >&2
    exit 1
fi
set -a
# shellcheck disable=SC1090
source "$OPERATOR_ENV"
set +a

# No operator note is consumed by the reset itself: the note was a `db
# bootstrap --operator-note` argument, and bootstrap moved into the
# operator's normal flow (bootstrap-if-needed gate). The script takes no
# arguments beyond the SENTIN8_DEV=1 guard.
COMPOSE_FILE="$GROUP_ROOT/docker-compose.yml"

CLI="$CLI_ROOT/target/debug/sentin8-cli"
[[ -x "$CLI" ]] || CLI="$CLI_ROOT/target/release/sentin8-cli"

# ── Step 1: stop the fleet (captain graceful; never pkill) ─────────────
# Success = either an explicit "captain is not running" (nothing was up) or
# the graceful-shutdown acknowledgement. Anything else means the operator
# must sign in first - the volume wipe must never run while captain is up.
if [[ -x "$CLI" ]]; then
    echo "[dev-destroy] stopping platform ..."
    STOP_OUT="$("$CLI" captain stop 2>&1 || true)"
    echo "$STOP_OUT"
    if ! echo "$STOP_OUT" | grep -q 'captain is not running' \
       && ! echo "$STOP_OUT" | grep -q 'captain stopped'; then
        echo "ERROR: could not stop the platform." >&2
        echo "Once bootstrapped, 'captain stop' requires a signed-in operator" >&2
        echo "with 'sentin8:captain:admin'. Run: $CLI signin" >&2
        echo "(approve the device flow in the browser), then re-run this script." >&2
        exit 1
    fi
else
    echo "[dev-destroy] CLI binary not found - skipping the stop step." >&2
    echo "(The volume wipe below also severs every fleet connection.)" >&2
fi

# ── Step 2: infra down + REMOVE VOLUMES (the actual destroy) ───────────
# `down -v` deletes the compose project's named volumes (sentin8-pgdata,
# sentin8-valkeydata): PostgreSQL comes back from a fresh initdb (role
# sentin8, db sentin8, zero service schemas) and Valkey from an empty
# data dir (zero ACL state). This is the WHOLE reset - no per-database
# DROPs, no role enumeration, no psql anywhere. Recreating the containers
# also rebuilds every bind-mount against the CURRENT .run/secrets tree,
# which kills the stale-mount class (postgres initdb EPERM crash-loop
# 2026-10-26; valkey 'unhealthy' with an empty /tls 2026-10-27) by
# construction instead of by patching.
echo "[dev-destroy] bringing infra down and removing volumes ..."
docker compose -f "$COMPOSE_FILE" down -v \
    || { echo "ERROR: 'docker compose down -v' failed." >&2; exit 1; }

# ── Step 3: ensure the infra TLS material (seeds ride this pass) ───────
# The material lives on the HOST (.run/secrets) and survives the wipe, but
# the reset RESEEDS pg_hba.conf/pg_ident.conf and re-mints/confirms the
# leaves so the fresh container generation binds to CURRENT material.
echo "[dev-destroy] ensuring infra TLS material (leaves + CA chain + hba/ident seeds) ..."
ACME="$GROUP_ROOT/sentin8-acme/target/debug/sentin8-acme"
[[ -x "$ACME" ]] || ACME="$GROUP_ROOT/sentin8-acme/target/release/sentin8-acme"
if [[ ! -x "$ACME" ]]; then
    echo "ERROR: $ACME not found - build first (make build in the sentin8/ group)." >&2
    exit 1
fi
"$ACME" --ensure-infra-tls \
    --mint-workloads=sentin8:acme,sentin8:ai,sentin8:app,sentin8:auth,sentin8:bff,sentin8:bus,sentin8:cron,sentin8:db,sentin8:flow,sentin8:func,sentin8:post,sentin8:proxy,sentin8:secrets,sentin8:stat,sentin8:storage,sentin8:sys,sentin8:web

# ── Step 4: infra up + wait for BOTH healthchecks green ──────────────────
echo "[dev-destroy] starting infra (fresh containers, virgin volumes) ..."
docker compose -f "$COMPOSE_FILE" up -d \
    || { echo "ERROR: 'docker compose up -d' failed." >&2; exit 1; }

# Fresh named volumes are root-owned; both containers run as the HOST user
# (1000:1000, compose `user:` - the 0600 TLS material demands it), and
# postgres initdb / valkey AOF writes fail EPERM against a root-owned data
# dir (the initdb EPERM crash-loop class, 2026-10-30). Fix the ownership
# ONCE here - deterministically, before the health wait, not by hand after
# a crash-loop. Best-effort: `docker run` needs a local alpine image only
# once; fall back to a chmod (777 on a dev-only disposable volume).
PGVOL="sentin8_sentin8-pgdata"
VKVOL="sentin8_sentin8-valkeydata"
echo "[dev-destroy] fixing fresh volume ownership (host uid) ..."
for vol in "$PGVOL" "$VKVOL"; do
    docker run --rm -v "$vol:/d" alpine chown 1000:1000 /d 2>/dev/null \
        || docker run --rm -v "$vol:/d" busybox chmod 777 /d 2>/dev/null \
        || echo "WARN: could not fix ownership of $vol - if postgres/valkey crash-loop, fix by hand: docker run --rm -v $vol:/d alpine chown 1000:1000 /d"
done
# A crash-looping container (started BEFORE the chown above landed) must be
# restarted once so initdb re-runs against the fixed permissions.
docker restart sentin8-postgres sentin8-valkey >/dev/null 2>&1 || true

echo "[dev-destroy] waiting for infra health ..."
deadline=$((SECONDS + 120))
until [[ "$(docker inspect -f '{{.State.Health.Status}}' sentin8-postgres 2>/dev/null)" == "healthy" \
      && "$(docker inspect -f '{{.State.Health.Status}}' sentin8-valkey 2>/dev/null)" == "healthy" ]]; do
    if (( SECONDS > deadline )); then
        echo "ERROR: infra did not become healthy in 120s." >&2
        echo "Check: docker compose -f $COMPOSE_FILE ps; docker logs sentin8-postgres; docker logs sentin8-valkey" >&2
        exit 1
    fi
    sleep 2
done

echo "[dev-destroy] done - infra is virgin (fresh initdb, empty Valkey)."
echo "Next: 'make enroll' (bootstraps + enrolls automatically), then 'make start'."