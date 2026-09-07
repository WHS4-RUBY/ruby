#!/bin/sh
set -eu

if [ "${1#-}" != "$1" ]; then
    set -- postgres "$@"
fi

if [ "$1" != "postgres" ]; then
    exec "$@"
fi

pgdata="${PGDATA:-/var/lib/postgresql/data}"
ready_file="/tmp/ruby-postgres-ready"
rm -f "$ready_file"
mkdir -p "$pgdata" /run/postgresql
chown -R postgres:postgres "$pgdata" /run/postgresql
chmod 0700 "$pgdata"

if [ ! -s "$pgdata/PG_VERSION" ]; then
    : "${POSTGRES_USER:?POSTGRES_USER is required}"
    : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
    database="${POSTGRES_DB:-$POSTGRES_USER}"
    password_file="$(mktemp)"
    trap 'rm -f "$password_file"' EXIT
    printf '%s\n' "$POSTGRES_PASSWORD" > "$password_file"
    chown postgres:postgres "$password_file"
    su-exec postgres initdb \
        -D "$pgdata" \
        --username="$POSTGRES_USER" \
        --pwfile="$password_file" \
        --auth-host=scram-sha-256 \
        --auth-local=trust \
        --encoding=UTF8 \
        --locale=C
    su-exec postgres pg_ctl -D "$pgdata" -o "-c listen_addresses=''" -w start
    if [ "$database" != "$POSTGRES_USER" ]; then
        su-exec postgres createdb --username="$POSTGRES_USER" --owner="$POSTGRES_USER" "$database"
    fi
    su-exec postgres pg_ctl -D "$pgdata" -m fast -w stop
    rm -f "$password_file"
    trap - EXIT
fi

if ! grep -qxF "host all all all scram-sha-256" "$pgdata/pg_hba.conf"; then
    printf '%s\n' "host all all all scram-sha-256" >> "$pgdata/pg_hba.conf"
fi

: "${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD is required}"
: "${POSTGRES_UNTRUSTED_PASSWORD:?POSTGRES_UNTRUSTED_PASSWORD is required}"
: "${POSTGRES_VERIFIER_PASSWORD:?POSTGRES_VERIFIER_PASSWORD is required}"
database="${POSTGRES_DB:-$POSTGRES_USER}"
su-exec postgres pg_ctl -D "$pgdata" -o "-c listen_addresses=''" -w start
su-exec postgres psql \
    --username="$POSTGRES_USER" \
    --dbname="$database" \
    --set=database="$database" \
    --set=owner="$POSTGRES_USER" \
    --set=app_password="$POSTGRES_APP_PASSWORD" \
    --set=untrusted_password="$POSTGRES_UNTRUSTED_PASSWORD" \
    --set=verifier_password="$POSTGRES_VERIFIER_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE ruby_app LOGIN PASSWORD %L', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ruby_app') \gexec
ALTER ROLE ruby_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'app_password';
SELECT format('CREATE ROLE ruby_untrusted LOGIN PASSWORD %L', :'untrusted_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ruby_untrusted') \gexec
ALTER ROLE ruby_untrusted WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'untrusted_password';
REVOKE ruby_untrusted FROM :"owner";
SELECT format('CREATE ROLE ruby_verifier LOGIN PASSWORD %L', :'verifier_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ruby_verifier') \gexec
ALTER ROLE ruby_verifier WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'verifier_password';
GRANT CONNECT ON DATABASE :"database" TO ruby_app, ruby_untrusted, ruby_verifier;
GRANT USAGE ON SCHEMA public TO ruby_app, ruby_untrusted, ruby_verifier;
GRANT CREATE ON SCHEMA public TO ruby_app;
DO $$
DECLARE item record;
BEGIN
    FOR item IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
    LOOP
        EXECUTE format('ALTER TABLE public.%I OWNER TO ruby_app', item.relname);
    END LOOP;
    FOR item IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'S'
    LOOP
        EXECUTE format('ALTER SEQUENCE public.%I OWNER TO ruby_app', item.relname);
    END LOOP;
END $$;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ruby_app WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ruby_app WITH GRANT OPTION;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ruby_verifier;
ALTER DEFAULT PRIVILEGES FOR ROLE ruby_app IN SCHEMA public
    GRANT SELECT ON TABLES TO ruby_verifier;
REVOKE SELECT ON pg_catalog.pg_stat_user_tables FROM PUBLIC;
REVOKE SELECT ON pg_catalog.pg_stat_all_tables FROM PUBLIC;
REVOKE SELECT ON pg_catalog.pg_statio_user_tables FROM PUBLIC;
REVOKE SELECT ON pg_catalog.pg_stat_xact_user_tables FROM PUBLIC;
SQL
su-exec postgres pg_ctl -D "$pgdata" -m fast -w stop

touch "$ready_file"
exec su-exec postgres "$@" -D "$pgdata" -c "listen_addresses=*"
