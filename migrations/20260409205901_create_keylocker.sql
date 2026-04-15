-- Add migration script here
CREATE TABLE keylocker (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ldata TEXT NOT NULL
);