CREATE TABLE gabriel_identity.mcp_connections (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    id uuid NOT NULL,
    name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_.-]{2,63}$'),
    endpoint text NOT NULL CHECK (endpoint ~ '^https://'),
    roles text[] NOT NULL CHECK (cardinality(roles) BETWEEN 1 AND 12 AND roles <@ ARRAY[
        'telemetry_health','alert_triage','incident_scoping','threat_intelligence','threat_hunting',
        'dfir_evidence','detection_engineering','exposure_vulnerability','identity_access',
        'cloud_supply_chain','response_remediation','recovery_learning']::text[]),
    auth_mode text NOT NULL CHECK (auth_mode IN ('none','bearer')),
    tool_manifest jsonb NOT NULL CHECK (jsonb_typeof(tool_manifest)='array'),
    tool_manifest_digest text,
    status text NOT NULL DEFAULT 'registered' CHECK (status IN ('registered','ready','degraded','revoked')),
    last_error text,
    checked_at timestamptz,
    created_by uuid NOT NULL,
    updated_by uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,name),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.users(organization_id,id),
    FOREIGN KEY (organization_id,updated_by) REFERENCES gabriel_identity.users(organization_id,id)
);
CREATE TABLE gabriel_identity.mcp_connection_secrets (
    organization_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    key_id text NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce)=12),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext)>16),
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (organization_id,connection_id),
    FOREIGN KEY (organization_id,connection_id) REFERENCES gabriel_identity.mcp_connections(organization_id,id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id,updated_by) REFERENCES gabriel_identity.users(organization_id,id)
);
REVOKE ALL ON gabriel_identity.mcp_connections,gabriel_identity.mcp_connection_secrets FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON gabriel_identity.mcp_connections,gabriel_identity.mcp_connection_secrets TO gabriel_identity_app;
