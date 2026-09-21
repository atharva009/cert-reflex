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
