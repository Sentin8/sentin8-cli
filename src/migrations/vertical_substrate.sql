-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
-- SPDX-License-Identifier: Apache-2.0

-- Vertical-database local substrate (/,
-- design/sentin8-vertical-data-plane-contract.md §VDC.6).
--
-- Applied by `sentin8-cli vertical init` to every VERTICAL database right
-- after public_helpers.sql, BEFORE any service SQL. It provisions the
-- runtime substrate tables a vertical service reads on its OWN hot path -
-- Shield policy substrate + the runtime registry replica - so no vertical
-- service ever reads the platform database:
--
--   sys.policy_sets / sys.policy_relations / sys.policy_principal_attrs
--     - the Shield substrate (crates/policy/src/lib.rs `load`,
--       substrate.rs `load_relations`/`load_principal_attrs`). Seeded from
--       each service's `--print-registration --section=policies|relations`
--       at init/enroll (single writer: enroll + the owning service's local
--       RFW policy-admin surface; consumers only read).
--   public.sentin8_boot_policy_load
--     - the SECURITY DEFINER boot loader (same contract as the platform
--       copy: filters `service = $1 AND enabled` server-side; a service
--       can only load its own rows).
--   sys.vertical_services
--     - the registry replica (read hot by `sentin8-config`
--       `resolve_subdomain`/`resolve_service_type`). Enroll is the single
--       writer (replicated from the platform registry rows).
--
-- Schema `sys` is namespace-only here: the vertical DB has NO
-- organizations/environments/services tables (VDC §VDC.1 - verticals own
-- their domain tables; tenant identity comes from ingress headers, events,
-- and `GET /v1/tenants/{env_id}`). The substrate tables carry no FKs to
-- platform tables; env_id values are plain UUIDs resolved per request.
--
-- RLS: the standard env-scoped context-gate set (same predicates as the
-- platform copies - `sentin8_context_initialized()`), so a vertical role's
-- reads are always tenant-bounded on the SAME database it owns.

CREATE SCHEMA IF NOT EXISTS sys;

-- ── Shield substrate: policy sets ────────────────────────────────────
CREATE TABLE IF NOT EXISTS sys.policy_sets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    service         TEXT NOT NULL,
    policy_set_name TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    policies        TEXT NOT NULL,
    schema          TEXT,
    origin          TEXT NOT NULL DEFAULT 'platform' CHECK (origin IN ('platform','tenant')),
    mode            TEXT NOT NULL DEFAULT 'shadow' CHECK (mode IN ('shadow','enforced')),
    version         INT NOT NULL DEFAULT 1,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, service, policy_set_name)
);

ALTER TABLE sys.policy_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.policy_sets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sentin8_policy_sets_select ON sys.policy_sets;
CREATE POLICY sentin8_policy_sets_select ON sys.policy_sets FOR SELECT
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_sets_insert ON sys.policy_sets;
CREATE POLICY sentin8_policy_sets_insert ON sys.policy_sets FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_sets_update ON sys.policy_sets;
CREATE POLICY sentin8_policy_sets_update ON sys.policy_sets FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_sets_delete ON sys.policy_sets;
CREATE POLICY sentin8_policy_sets_delete ON sys.policy_sets FOR DELETE
    USING (sentin8_context_initialized());

-- ── Shield substrate: ReBAC relation tuples ──────────────────────────
CREATE TABLE IF NOT EXISTS sys.policy_relations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id       UUID NOT NULL,
    service      TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id   TEXT NOT NULL,
    relation     TEXT NOT NULL,
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    origin       TEXT NOT NULL DEFAULT 'platform' CHECK (origin IN ('platform','tenant')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, subject_type, subject_id, relation, object_type, object_id)
);

ALTER TABLE sys.policy_relations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.policy_relations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sentin8_policy_relations_select ON sys.policy_relations;
CREATE POLICY sentin8_policy_relations_select ON sys.policy_relations FOR SELECT
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_relations_insert ON sys.policy_relations;
CREATE POLICY sentin8_policy_relations_insert ON sys.policy_relations FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_relations_update ON sys.policy_relations;
CREATE POLICY sentin8_policy_relations_update ON sys.policy_relations FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_relations_delete ON sys.policy_relations;
CREATE POLICY sentin8_policy_relations_delete ON sys.policy_relations FOR DELETE
    USING (sentin8_context_initialized());

-- ── Shield substrate: principal attributes ───────────────────────────
CREATE TABLE IF NOT EXISTS sys.policy_principal_attrs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    subject_id  TEXT NOT NULL,
    attr_key    TEXT NOT NULL,
    attr_value  JSONB NOT NULL,
    origin      TEXT NOT NULL DEFAULT 'platform' CHECK (origin IN ('platform','tenant')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, subject_id, attr_key)
);

ALTER TABLE sys.policy_principal_attrs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.policy_principal_attrs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sentin8_policy_attrs_select ON sys.policy_principal_attrs;
CREATE POLICY sentin8_policy_attrs_select ON sys.policy_principal_attrs FOR SELECT
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_attrs_insert ON sys.policy_principal_attrs;
CREATE POLICY sentin8_policy_attrs_insert ON sys.policy_principal_attrs FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_attrs_update ON sys.policy_principal_attrs;
CREATE POLICY sentin8_policy_attrs_update ON sys.policy_principal_attrs FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS sentin8_policy_attrs_delete ON sys.policy_principal_attrs;
CREATE POLICY sentin8_policy_attrs_delete ON sys.policy_principal_attrs FOR DELETE
    USING (sentin8_context_initialized());

-- ── SECURITY DEFINER boot loader (same contract as the platform copy) ──
-- `PolicyEngine::load` runs at service boot, before any tenant context -
-- RLS would hide every row from a NOBYPASSRLS role. This function filters
-- `service = $1 AND enabled` SERVER-SIDE (a service loads only its own
-- rows) and is granted EXECUTE to every service role below.
CREATE OR REPLACE FUNCTION public.sentin8_boot_policy_load(p_service TEXT)
RETURNS TABLE (
    id              UUID,
    env_id          UUID,
    service         TEXT,
    policy_set_name TEXT,
    description     TEXT,
    policies        TEXT,
    schema          TEXT,
    origin          TEXT,
    mode            TEXT,
    version         INT,
    enabled         BOOLEAN
)
LANGUAGE sql SECURITY DEFINER SET search_path = sys, public AS $func$
    SELECT id, env_id, service, policy_set_name, description,
           policies, schema, origin, mode, version, enabled
      FROM sys.policy_sets
     WHERE service = p_service AND enabled;
$func$;

GRANT EXECUTE ON FUNCTION public.sentin8_boot_policy_load(TEXT) TO sentin8_app_dev;
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT rolname FROM pg_roles
             WHERE rolname LIKE '%_service'
               AND rolname NOT LIKE 'pg_%'
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.sentin8_boot_policy_load(TEXT) TO %I', r.rolname);
    END LOOP;
EXCEPTION WHEN undefined_function THEN NULL;
END $$;

-- ── Registry replica: sys.vertical_services ─────────────────────────
-- Written by enroll from the platform registry rows (single writer);
-- read hot by `sentin8-config` resolve_subdomain / resolve_service_type
-- on the service's OWN pool - local on a vertical DB, platform on a
-- platform service (the same code path serves both).
CREATE TABLE IF NOT EXISTS sys.vertical_services (
    vertical      TEXT NOT NULL,
    service_type  TEXT NOT NULL,
    subdomain     TEXT NOT NULL DEFAULT '',
    health_path   TEXT NOT NULL DEFAULT '/v1/health',
    admin_ui      JSONB,
    PRIMARY KEY (vertical, service_type)
);

ALTER TABLE sys.vertical_services ENABLE ROW LEVEL SECURITY;
ALTER TABLE sys.vertical_services FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sentin8_vertical_services_select ON sys.vertical_services;
CREATE POLICY sentin8_vertical_services_select ON sys.vertical_services FOR SELECT
    USING (sentin8_context_initialized());

-- ── Grants: every service role reads the substrate ───────────────────
-- The Shield engine reads relations/attrs per request under the service's
-- own role (RLS bounds reads to the caller's tenant); `policy_sets` rides
-- the boot loader. The loop grants EVERY `*_service` role (cluster-wide
-- names): roles from OTHER verticals are inert here - they connect to
-- their own databases (fail-fast), so a grant in this database is
-- unreachable surface-by-accident, and a fresh vertical DB has no rows to
-- leak anyway. RLS still gates every read to an initialized tenant
-- context.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT rolname FROM pg_roles
             WHERE rolname LIKE '%_service'
               AND rolname NOT LIKE 'pg_%'
    LOOP
        EXECUTE format(
            'GRANT USAGE ON SCHEMA sys TO %I', r.rolname);
        EXECUTE format(
            'GRANT SELECT ON sys.policy_relations, sys.policy_principal_attrs, sys.vertical_services TO %I',
            r.rolname);
        -- Per-env policy-set seeding (event-driven env-init, VDC §VDC.6):
        -- each vertical service copies its SYSTEM-env `origin='platform'`
        -- sets into a newly enabled env - the vertical-DB mirror of what
        -- Sentin8:Sys does for the platform DB at env creation. SELECT
        -- (the INSERT..SELECT reads the SYSTEM template), INSERT + UPDATE
        -- only (enroll remains the only DELETE path); the RLS context-gate
        -- policies above scope writes to initialized contexts.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON sys.policy_sets TO %I', r.rolname);
    END LOOP;
EXCEPTION WHEN undefined_table THEN NULL;
END $$;