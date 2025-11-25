-- +migrate Up
CREATE TABLE cryptographic_keys (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    algorithm VARCHAR(20) NOT NULL,
    key_size INTEGER NOT NULL,
    usage VARCHAR(20) NOT NULL,
    public_key BYTEA NOT NULL,
    key_handle VARCHAR(100) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB,
    
    -- Índices para búsquedas eficientes
    CONSTRAINT unique_key_handle UNIQUE (key_handle)
);

CREATE INDEX idx_cryptographic_keys_tenant ON cryptographic_keys(tenant_id);
CREATE INDEX idx_cryptographic_keys_algorithm ON cryptographic_keys(algorithm);
CREATE INDEX idx_cryptographic_keys_created_at ON cryptographic_keys(created_at);
CREATE INDEX idx_cryptographic_keys_active ON cryptographic_keys(is_active) WHERE is_active = true;

-- +migrate Down
DROP TABLE cryptographic_keys;