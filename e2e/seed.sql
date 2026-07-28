-- Source-cluster fixture for the e2e harness. Shapes mirror the production
-- validation contract: refinery migration tables at the drill's floor
-- values (cloud-api 63/62, chat-api 34/33), rename sentinels, uuid-ossp,
-- a token column for the chat-api format check, and NO response_authors.

CREATE ROLE datadog LOGIN PASSWORD 'e2e-datadog-pw';

-- db "postgres" == cloud-api
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE refinery_schema_history (
    version int PRIMARY KEY,
    name text,
    applied_on timestamptz DEFAULT now(),
    checksum text
);
INSERT INTO refinery_schema_history (version, name, checksum)
SELECT g, 'm' || g, md5(g::text) FROM generate_series(2, 63) g;

CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO organizations (name) SELECT 'org-' || g FROM generate_series(1, 25) g;
CREATE INDEX organizations_name_idx ON organizations (name);

CREATE TABLE users (
    id bigserial PRIMARY KEY,
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO users (email) SELECT 'user' || g || '@example.test' FROM generate_series(1, 40) g;

CREATE TABLE refresh_tokens (
    id bigserial PRIMARY KEY,
    user_id bigint REFERENCES users (id),
    token_hash text,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO refresh_tokens (user_id, token_hash)
SELECT g, md5(g::text) FROM generate_series(1, 5) g;

CREATE TABLE model_history (
    id bigserial PRIMARY KEY,
    model text,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO model_history (model) VALUES ('m1'), ('m2');

-- db "chat_api"
CREATE DATABASE chat_api;
\connect chat_api

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE refinery_schema_history (
    version int PRIMARY KEY,
    name text,
    applied_on timestamptz DEFAULT now(),
    checksum text
);
INSERT INTO refinery_schema_history (version, name, checksum)
SELECT g, 'm' || g, md5(g::text) FROM generate_series(2, 34) g;

CREATE TABLE users (
    id bigserial PRIMARY KEY,
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO users (email) SELECT 'chat' || g || '@example.test' FROM generate_series(1, 15) g;

CREATE TABLE sessions (
    id bigserial PRIMARY KEY,
    user_id bigint REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO sessions (user_id) SELECT (g % 15) + 1 FROM generate_series(1, 30) g;

CREATE TABLE conversations (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    title text,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO conversations (title) SELECT 'conv-' || g FROM generate_series(1, 10) g;

CREATE TABLE agent_instances (
    id bigserial PRIMARY KEY,
    name text,
    token text,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO agent_instances (name, token)
SELECT 'agent-' || g, md5(g::text) || md5((g + 1)::text) FROM generate_series(1, 8) g;

-- db "rag_service" (no migrations table, no app contract: existence,
-- error-free restore + index count only)
CREATE DATABASE rag_service;
\connect rag_service

CREATE TABLE documents (
    id bigserial PRIMARY KEY,
    title text,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO documents (title) SELECT 'doc-' || g FROM generate_series(1, 7) g;
CREATE INDEX documents_title_idx ON documents (title);
