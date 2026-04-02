-- Add migration script here
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    login TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    reset_email TEXT
);