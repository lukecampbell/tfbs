-- Add migration script here
ALTER TABLE users ADD CONSTRAINT unique_login UNIQUE(login);