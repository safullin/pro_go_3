ALTER TABLE secrets ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS metadata TEXT NOT NULL DEFAULT '';

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS secrets_name_trgm_idx ON secrets USING GIN (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS secrets_metadata_trgm_idx ON secrets USING GIN (metadata gin_trgm_ops);
