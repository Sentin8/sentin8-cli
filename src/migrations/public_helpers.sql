-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
-- SPDX-License-Identifier: Apache-2.0

-- Per-database `public` schema helpers (DBX, architecture-principles §6.6).
--
-- Applied to EVERY database the platform touches: `db sentin8` (by platform.sql
-- which embeds the same definitions) and each vertical database (by
-- `sentin8-cli vertical init`). RLS helper functions resolve via every
-- service role's search_path (`{service}, public`).

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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
    -- EXPLICIT argument overwrites.
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
    PERFORM set_config('app.staff_override', 'false', true);
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

-- Note: `sentin8_current_org_id` references sys.environments and is defined
-- ONLY in db sentin8 (platform.sql) - vertical databases resolve org via the
-- platform API, never a cross-database read.

-- DBX outbox relay (§6.7): the per-service relay task drains its LOCAL
-- `{service}.outbox`, but the table is FORCE-RLS'd on (context_initialized,
-- env_id) and the relay holds NO tenant context - a bare-pool SELECT
-- silently returns 0 rows (incident 2026-09-23: unrelayed rows accumulated
-- fleet-wide; identity:updated invalidation events never reached Bus).
-- This owner-side SECURITY DEFINER helper returns the DISTINCT env_ids of
-- unrelayed rows so the relay can set context per env and drain each.
-- SECURITY: returns env UUIDs only - no row content; callers already hold
-- the per-service role that owns the table.
CREATE OR REPLACE FUNCTION public.sentin8_outbox_unrelayed_envs(
    p_schema TEXT DEFAULT NULL
) RETURNS TABLE (env_id UUID) AS $$
DECLARE
    v_table TEXT;
BEGIN
    -- Resolve the caller's own schema from search_path when not given:
    -- the outbox lives in the CALLING service's schema (`{leaf}.outbox`,
    -- shell §8b spawns the DBX relay against the service's own schema).
    -- NOTE: probe `{leaf}.outbox` ONLY - some services own an unrelated
    -- domain `{leaf}.inbox` table (post's delivery inbox has no `relayed`
    -- column); probing inbox first made the helper fail with
    -- `column "relayed" does not exist` for those services and their
    -- DBX relay never drained (incident 2026-09-23).
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
-- ── Registry reads ───────────────────────────────────────────────────────
-- RETIRED (design/sentin8-vertical-data-plane-contract.md §VDC.6):
-- the former `sentin8_registry_read(TEXT, uuid)` SECURITY DEFINER helper
-- read `sys.services`/`sys.environments` - platform-database tables -
-- but this file is applied to VERTICAL databases where those tables do
-- not exist; a SECURITY DEFINER function cannot cross databases, so the
-- helper failed at runtime for every vertical caller (zero callers
-- existed in either workspace). Its needs are served by:
-- • `GET /v1/tenants/{env_id}` - Sys tenant-snapshot API (scope
--     `sentin8:sys:tenants:read`), for on-demand reads + initial snapshot;
-- • payload-complete `sentin8: sys: org/env: *` events, for
--     reactions;
-- • the local substrate replica (/), for hot-path reads.
-- Do NOT re-add a cross-database registry reader here.
