-- +goose Up
ALTER TABLE users
ADD COLUMN hashed_password TEXT DEFAULT 'unset' NOT NULL;
