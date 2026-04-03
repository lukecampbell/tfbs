CREATE TABLE users (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    login TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    reset_email TEXT
);
