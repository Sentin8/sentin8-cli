-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8 platform database (`db sentin8`) initialization script (DBX).
--
-- Creates, in THIS database only:
--   * extensions + RLS helper functions in `public` (provisioned once per
--     database - `db sentin8` here, each vertical database at `vertical init`)
--   * one schema per platform service: auth, sys, bus, post, stat, db,
--     flow, func, cron, app, bff, secrets, storage, ai, tls, proxy
--   * per-service PostgreSQL roles (cluster-wide) with per-database
--     search_path + grants
--   * the runtime registry tables in schema `sys`
--
-- NO role carries BYPASSRLS (DBX - architecture-principles §6.6/§6.7): the
-- former `sentin8_bus_relay`/`sentin8_post_relay` relay roles are retired;
-- bus/post drain their OWN tables under their own service roles, and
-- producers publish events via `POST /v1/produce` (local outbox + produce
-- API, §6.7) - no shared inbox table exists.
--
-- Vertical databases (bank8, hotel8, …) are created by
-- `sentin8-cli vertical init` - this script never touches them
-- (zero compile-time vertical knowledge, §4.14).

-- ── Extensions ──────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Per-service schemas ─────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS sys;
CREATE SCHEMA IF NOT EXISTS bus;
CREATE SCHEMA IF NOT EXISTS post;
CREATE SCHEMA IF NOT EXISTS stat;
CREATE SCHEMA IF NOT EXISTS db;
CREATE SCHEMA IF NOT EXISTS flow;
CREATE SCHEMA IF NOT EXISTS func;
CREATE SCHEMA IF NOT EXISTS cron;
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS bff;
CREATE SCHEMA IF NOT EXISTS secrets;
CREATE SCHEMA IF NOT EXISTS storage;
CREATE SCHEMA IF NOT EXISTS ai;
CREATE SCHEMA IF NOT EXISTS tls;
CREATE SCHEMA IF NOT EXISTS proxy;

-- ── RLS helper functions (public schema - every role's search_path) ──────
-- Called by every service before repository operations (§4.3d).
--
-- p_stream_family (9th arg, STREAM-FAM-1/3): transaction-local
-- app.stream_family GUC. Under DBX the shared-inbox RLS policies that read
-- it are retired - the GUC now only labels a producer's OWN local outbox
-- rows (convenience: the service's context setter can stamp the family).
-- NULL preserves the role-level default (STREAM-FAM-3 clobber fix).
DROP FUNCTION IF EXISTS public.sentin8_set_tenant_context(
    uuid, text, text, text, boolean, boolean, boolean, uuid
);
CREATE OR REPLACE FUNCTION public.sentin8_set_tenant_context(
    p_env_id UUID,
    p_subject_id TEXT DEFAULT NULL,
    p_token_tp TEXT DEFAULT NULL,
    p_scopes TEXT DEFAULT NULL,
    p_is_platform_admin BOOLEAN DEFAULT FALSE,
    p_bypass_rls BOOLEAN DEFAULT FALSE,
    p_is_env_admin BOOLEAN DEFAULT FALSE,
    p_sentin8_auth_user_id UUID DEFAULT NULL,
    p_stream_family TEXT DEFAULT NULL,
    p_staff_override BOOLEAN DEFAULT FALSE
) RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.env_id', p_env_id::TEXT, true);
    PERFORM set_config('app.subject_id', COALESCE(p_subject_id, ''), true);
    PERFORM set_config('app.token_tp', COALESCE(p_token_tp, ''), true);
    PERFORM set_config('app.scopes', COALESCE(p_scopes, ''), true);
    PERFORM set_config('app.is_platform_admin', p_is_platform_admin::TEXT, true);
    -- Staff-override stamp (isolation-design §10.1): set by a service
    -- handler AFTER it validated the caller's org relationship for a
    -- cross-env read - the RLS policies admit stamped requests for the
    -- overridden env only. Never set from a caller-supplied value.
    PERFORM set_config('app.staff_override', p_staff_override::TEXT, true);
    PERFORM set_config('app.bypass_rls', p_bypass_rls::TEXT, true);
    PERFORM set_config('app.is_env_admin', p_is_env_admin::TEXT, true);
    PERFORM set_config('app.sentin8_auth_user_id', COALESCE(p_sentin8_auth_user_id::TEXT, ''), true);
    -- STREAM-FAM-3: NULL preserves the role/session-level default; only an
    -- EXPLICIT argument overwrites (writing '' would clobber the role
    -- default for the rest of the connection).
    IF p_stream_family IS NOT NULL THEN
        PERFORM set_config('app.stream_family', p_stream_family, true);
    END IF;
    PERFORM set_config('app.context_initialized', 'true', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.sentin8_clear_tenant_context() RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.env_id', '', true);
    PERFORM set_config('app.subject_id', '', true);
    PERFORM set_config('app.token_tp', '', true);
    PERFORM set_config('app.scopes', '', true);
    PERFORM set_config('app.is_platform_admin', 'false', true);
    PERFORM set_config('app.bypass_rls', 'false', true);
    PERFORM set_config('app.is_env_admin', 'false', true);
    PERFORM set_config('app.sentin8_auth_user_id', '', true);
    -- app.stream_family: re-derive the ROLE-level default from pg_roles
    -- (STREAM-FAM-3 - a '' write would override it for the session).
    PERFORM set_config(
        'app.stream_family',
        COALESCE(
            (SELECT split_part(setting, 'app.stream_family=', 2)
               FROM unnest(rolconfig) AS setting
              WHERE setting LIKE 'app.stream_family=%'
              LIMIT 1),
            ''
        ),
        true
    )
    FROM pg_roles WHERE rolname = current_user;
    PERFORM set_config('app.context_initialized', 'false', true);
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.sentin8_context_initialized() RETURNS BOOLEAN AS $$
BEGIN
    RETURN current_setting('app.context_initialized', true) = 'true';
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.sentin8_current_env_id() RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.env_id', true), '')::UUID;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Org resolver - SECURITY DEFINER to avoid self-referential policy
-- recursion on environments/organizations lookups.
CREATE OR REPLACE FUNCTION public.sentin8_current_org_id() RETURNS UUID AS $$
BEGIN
    RETURN (SELECT org_id FROM sys.environments
             WHERE id = sentin8_current_env_id());
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Bypass is inert by design (Delegation Gateway replaced it) - kept for
-- policy-text compatibility; always FALSE.
CREATE OR REPLACE FUNCTION public.sentin8_bypass_rls() RETURNS BOOLEAN AS $$
BEGIN
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.sentin8_current_subject_id() RETURNS TEXT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.subject_id', true), '');
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.sentin8_current_sentin8_auth_user_id() RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.sentin8_auth_user_id', true), '')::UUID;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.sentin8_is_env_admin() RETURNS BOOLEAN AS $$
BEGIN
    RETURN current_setting('app.is_env_admin', true) = 'true';
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- EXACT scope-set membership (incident 2026-08-28 RC7/F7: the old LIKE
-- form let longer scopes satisfy shorter checks).
CREATE OR REPLACE FUNCTION public.sentin8_has_scope(p_scope TEXT) RETURNS BOOLEAN AS $$
BEGIN
    RETURN p_scope = ANY (string_to_array(current_setting('app.scopes', true), ' '));
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.sentin8_current_token_tp() RETURNS TEXT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.token_tp', true), '');
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Domain resolver NOTIFY trigger function - RETIRED (SBI-SYS-1, kept as a
-- harmless no-op for old trigger rows that may survive a partial teardown):
-- domain-changed notifications ride MemBus now
-- (`mchan:{SYSTEM_ENV_SLUG}:sys-domain`, sys design §9/§10; membus design
-- §4). Services subscribe via sentin8-membus; cache misses resolve through
-- sys's `GET /v1/resolve/hostname` (SBI-SYS-2) - no sys.* table grants.
CREATE OR REPLACE FUNCTION public.sentin8_notify_domain_changed() RETURNS trigger AS $$
BEGIN
    RETURN NEW; -- retired: MemBus carries domain-changed (SBI-SYS-1)
END;
$$ LANGUAGE plpgsql;

-- ── migrations tracking (schema sys) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS sys.migrations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service      TEXT NOT NULL,
    filename     TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (service, filename)
);

-- ── Runtime registry tables (schema sys) ────────────────────────────────
-- Populated by `sentin8-cli vertical enroll`. Platform-level (no RLS -
-- operator-gated via the signed-in CLI/HTTP pipeline).

-- ── Per-service PostgreSQL roles (cluster-wide; NOBYPASSRLS always) ──────
-- DBX: no relay roles, no BYPASSRLS anywhere. Each role's grants live
-- in this database only (vertical databases get their own).
--
-- PostgreSQL certificate identity (group DESIGN.md §3.2): every role is
-- PASSWORDLESS - `db bootstrap` writes the matching `pgm` identity-map
-- row (CN `m2m-{workload}` → role) into `pg_ident.conf`, and the TLS
-- handshake's `cert` auth method decides the connection. There is no
-- SCRAM hash to converge (the class of fleet-stranding incidents the
-- old password-convergence block patched cannot recur: no password
-- exists anywhere on the plane).
DO $$
BEGIN
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_auth_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_auth_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_sys_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_sys_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_stat_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_stat_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_cron_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_cron_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_flow_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_flow_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_func_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_func_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_db_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_db_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_storage_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_storage_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_tls_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_tls_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_app_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_app_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_post_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_post_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_bus_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_bus_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_bff_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_bff_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_secrets_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_secrets_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_sign_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_sign_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_ai_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_ai_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_captain_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_captain_service LOGIN NOBYPASSRLS; END IF;
    -- Bootstrap-tier + gateway roles referenced from the operator's
    -- per-service DSN env vars (VDC §VDC.3b): platform.sql seeds ALL
    -- platform `_service` roles - the bootstrap tier creates the token
    -- plane and presents the workload certificates minted by
    -- `make infra-tls` (group DESIGN.md §3.2 - no SCRAM bootstrap step
    -- exists).
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_proxy_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_proxy_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_acme_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_acme_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_web_service';
    IF NOT FOUND THEN CREATE ROLE sentin8_web_service LOGIN NOBYPASSRLS; END IF;
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_app_dev';
    IF NOT FOUND THEN CREATE ROLE sentin8_app_dev LOGIN NOBYPASSRLS; END IF;
    -- Legacy shared dev roles (sentin8-config default_database_url):
    -- sentin8_app was historically created out-of-band; a FRESH database
    -- never had it, and the CONNECT grant below then failed bootstrap
    -- (role "sentin8_app" does not exist). Seeded here alongside
    -- sentin8_app_dev so bootstrap is self-contained on a fresh cluster.
    PERFORM 1 FROM pg_roles WHERE rolname = 'sentin8_app';
    IF NOT FOUND THEN CREATE ROLE sentin8_app LOGIN NOBYPASSRLS; END IF;
END $$;

-- ── Per-role search_path (per database) ─────────────────────────────────
-- PLATFORM-OWNED identities only. Service roles' search_paths + grants
-- are SERVICE-OWNED: each service's init.sql / --print-registration
-- declares and applies them (self-registration REG-15; the strip was the
-- 2026-10-03 service-ownership pass). The bootstrap tier (roles that must
-- exist BEFORE any service can self-describe) keeps its identity here:
ALTER ROLE sentin8_acme_service   SET search_path = public;
ALTER ROLE sentin8_web_service    SET search_path = public;
ALTER ROLE sentin8_proxy_service  SET search_path = public;
ALTER ROLE sentin8_captain_service SET search_path = sys, public;
-- Shared dev roles (sentin8-config default_database_url). DISTINCT
-- postures (operator decision 2026-10-03, stricter posture):
--   sentin8_app      - the DEV SERVICE RUNTIME DSN: RLS-bounded access.
--     Sees the schemas + registry tables and reaches tenant data ONLY
--     through RLS (NOBYPASSRLS + FORCE RLS) - a service running under it
--     exercises the same row policies as its OAuth role would.
--   sentin8_app_dev  - the TEST-HARNESS DSN (DBX-CLI-6): full DML across
--     the platform schemas for local tests/fixtures.
ALTER ROLE sentin8_app     SET search_path = auth, sys, bus, post, stat, db, flow, func, cron, app, bff, secrets, storage, ai, tls, proxy, public;
ALTER ROLE sentin8_app_dev SET search_path = auth, sys, bus, post, stat, db, flow, func, cron, app, bff, secrets, storage, ai, tls, proxy, public;
-- The superuser (DDL/migrations) sees this database's schemas unqualified.
ALTER ROLE sentin8 SET search_path = auth, sys, bus, post, stat, db, flow, func, cron, app, bff, secrets, storage, ai, tls, proxy, public;

-- ── Schema USAGE ─────────────────────────────────────────────────────────
-- PLATFORM-OWNED only: public (shared RLS helpers) for the bootstrap tier
-- + the test-harness role. Each service role's OWN-schema USAGE is
-- declared by the service (init.sql / --print-registration) and applied
-- at enroll - the per-service USAGE blocks were stripped in the
-- 2026-10-03 service-ownership pass.
GRANT USAGE ON SCHEMA public TO
    sentin8_acme_service, sentin8_web_service, sentin8_proxy_service,
    sentin8_captain_service, sentin8_app_dev;
-- Dev/operator roles (sentin8-config default_database_url DSNs) need
-- USAGE across the platform schemas: the CLI's scout/enroll queries run
-- under the operator DSN and read `sys.*` (fresh-DB defect - these grants
-- were historically applied out-of-band, so a clean bootstrap left the
-- operator unable to even read the scout).
GRANT USAGE ON SCHEMA auth, sys, bus, post, stat, db, flow, func, cron,
    app, bff, secrets, storage, ai, tls, proxy
    TO sentin8_app, sentin8_app_dev;

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO
    sentin8_acme_service, sentin8_web_service, sentin8_proxy_service,
    sentin8_captain_service, sentin8_app_dev;
-- Dev/operator roles: EXECUTE on every platform schema's functions (the
-- RLS helpers live per-schema too, not just public).
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA auth, sys, bus, post, stat,
    db, flow, func, cron, app, bff, secrets, storage, ai, tls, proxy
    TO sentin8_app, sentin8_app_dev;

-- Platform `sentin8_*_service` roles also need CONNECT on the platform
-- database (the PUBLIC revoke above removed the default) - grant it to
-- every platform service role; vertical roles never receive it.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT rolname FROM pg_roles
             WHERE rolname LIKE 'sentin8\_%\_service'
               AND rolname NOT LIKE 'pg_%'
    LOOP
        EXECUTE format('GRANT CONNECT ON DATABASE sentin8 TO %I', r.rolname);
    END LOOP;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

-- ── Platform-database CONNECT boundary (/, design/
-- sentin8-vertical-data-plane-contract.md) ─────────────────────────────
-- The platform database is PLATFORM-ONLY. PUBLIC's default CONNECT is
-- revoked; connect is granted to the superuser/DDL roles, the shared dev
-- role, and every platform `sentin8_*_service` role (dynamic loop covers
-- late-created ones at enroll). A VERTICAL role can never hold CONNECT
-- here - a vertical process cannot open any connection to db `sentin8`
-- (the DSN fail-fast covers config; this covers the database itself).
REVOKE CONNECT ON DATABASE sentin8 FROM PUBLIC;
GRANT CONNECT ON DATABASE sentin8 TO sentin8, sentin8_app, sentin8_app_dev,
    sentin8_acme_service, sentin8_web_service, sentin8_proxy_service,
    sentin8_captain_service;
DO $$ BEGIN
    EXECUTE 'GRANT CONNECT ON DATABASE sentin8 TO sentin8_app_dev';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

-- ── Cross-service table grants - SERVICE-OWNED (2026-10-03 strip) ────────
-- Every cross-schema grant is declared by the CONSUMING service's
-- registration (PgRole::cross_schema_grants) and applied by enroll's
-- phase-2 convergence pass - platform.sql no longer hardcodes any of
-- them. Own-schema DML lives in each service's init.sql. Acme's former
-- bus.inbox INSERT grant is RETIRED entirely (D1: local outbox + the
-- produce API now).

-- ── Final reconciliation pass ─────────────────────────────────────────────
-- Service init.sql creates tables AFTER this script ran; each service's
-- OWN init.sql grants its role DML on them (service-owned since the
-- 2026-10-03 strip). The only platform-owned reconciliation is the
-- test-harness role:
DO $$
BEGIN
    EXECUTE 'GRANT USAGE ON SCHEMA auth, sys, bus, post, stat, db, flow, func, cron, app, bff, secrets, storage, ai, tls, proxy TO sentin8_app_dev';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth, sys, bus, post, stat, db, flow, func, cron, app, bff, secrets, storage, ai, tls, proxy TO sentin8_app_dev';
    EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA auth, sys, bus, post, stat, db, flow, func, cron, app, bff, secrets, storage, ai, tls, proxy TO sentin8_app_dev';
END $$;

-- ── Sentin8:Policy boot loader (policy design §4.2b-r) ────────────────────
-- Created at bootstrap so services can COMPILE+BOOT before sys's init.sql has
-- run (sqlx macros + PolicyEngine::load resolve this function). Returns zero
-- rows until sys.policy_sets exists; sys's init.sql re-creates the
-- authoritative version after its table exists.
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
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = sys, public AS $func$
BEGIN
    RETURN QUERY
        SELECT ps.id, ps.env_id, ps.service, ps.policy_set_name, ps.description,
               ps.policies, ps.schema, ps.origin, ps.mode, ps.version, ps.enabled
          FROM sys.policy_sets ps
         WHERE ps.service = p_service AND ps.enabled;
EXCEPTION
    WHEN undefined_table THEN
        -- sys's init.sql has not run yet - zero policy rows is fail-closed
        -- correct on a pre-enroll bootstrap (nothing can be authorized anyway).
        RETURN;
END;
$func$;

-- ── DBX outbox relay helper (§6.7, incident 2026-09-23) ───────────────────
-- Owner-side SECURITY DEFINER helper: returns the DISTINCT env_ids of
-- unrelayed rows in the CALLING service's `{leaf}.outbox` so the per-service
-- DBX relay can set tenant context per env and drain each (the outbox is
-- FORCE-RLS'd; a bare-pool SELECT silently returns 0 rows). Probes
-- `{leaf}.outbox` ONLY - some services own an unrelated `{leaf}.inbox` domain
-- table without a `relayed` column. Canonical definition lives in
-- public_helpers.sql (applied to every vertical DB by vertical init/enroll);
-- this bootstrap-time copy covers db sentin8 (the `sentin8` vertical skips
-- the vertical-DB apply because its database pre-exists).
CREATE OR REPLACE FUNCTION public.sentin8_outbox_unrelayed_envs(
    p_schema TEXT DEFAULT NULL
) RETURNS TABLE (env_id UUID) AS $$
DECLARE
    v_table TEXT;
BEGIN
    v_table := COALESCE(p_schema, split_part(current_setting('search_path', true), ',', 1));
    -- A schema without an `outbox` table (services that publish no events -
    -- e.g. flow, whose dead outbox was removed) drains ZERO rows instead of
    -- erroring the relay every poll.
    BEGIN
        RETURN QUERY EXECUTE format(
            'SELECT DISTINCT env_id FROM %I.outbox WHERE relayed = false', v_table);
    EXCEPTION WHEN undefined_table OR undefined_column THEN
        RETURN;
    END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
