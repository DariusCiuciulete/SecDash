-- Initialize TimescaleDB and create Keycloak database
SELECT 'CREATE DATABASE keycloak' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'keycloak')\gexec
GRANT ALL PRIVILEGES ON DATABASE keycloak TO secdash;

-- Enable TimescaleDB extension on main database
\c secdash;
CREATE EXTENSION IF NOT EXISTS timescaledb;
