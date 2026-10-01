BEGIN;

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE users ALTER COLUMN password_hash DROP DEFAULT;

ALTER TABLE devices ADD COLUMN IF NOT EXISTS public_key TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS key_id TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS key_algorithm TEXT NOT NULL DEFAULT 'Ed25519';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_key_id ON devices(key_id) WHERE key_id IS NOT NULL;

ALTER TABLE witness_observations ADD COLUMN IF NOT EXISTS nonce TEXT;
ALTER TABLE witness_observations ADD COLUMN IF NOT EXISTS observation_type TEXT NOT NULL DEFAULT 'ble_proximity';
ALTER TABLE witness_observations ADD COLUMN IF NOT EXISTS protocol_version TEXT NOT NULL DEFAULT '1';
ALTER TABLE witness_observations ADD COLUMN IF NOT EXISTS ephemeral_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_witness_nonce ON witness_observations(nonce) WHERE nonce IS NOT NULL;

ALTER TABLE attendance_records ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES devices(id) ON DELETE RESTRICT;
ALTER TABLE attendance_records ADD COLUMN IF NOT EXISTS proof_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS device_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    key_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    session_id UUID REFERENCES class_sessions(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_device_challenges_user ON device_challenges(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_device_challenges_session ON device_challenges(session_id);

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';

COMMIT;
