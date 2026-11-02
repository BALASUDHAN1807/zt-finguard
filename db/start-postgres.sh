#!/bin/sh
# Postgres refuses a TLS key that others can read, and mounted secrets keep
# the host's file mode. Copy the key into a tmpfs owned by postgres with 0600,
# then hand over to the official entrypoint (which drops to the postgres user).
set -eu
install -d -o postgres -g postgres -m 0700 /var/run/postgresql/tls
install -o postgres -g postgres -m 0600 /run/secrets/tls_key /var/run/postgresql/tls/server.key
install -o postgres -g postgres -m 0644 /run/secrets/tls_crt /var/run/postgresql/tls/server.crt
install -o postgres -g postgres -m 0644 /run/secrets/ca_crt  /var/run/postgresql/tls/ca.crt

exec docker-entrypoint.sh postgres \
  -c listen_addresses='*' \
  -c ssl=on \
  -c ssl_min_protocol_version=TLSv1.3 \
  -c ssl_cert_file=/var/run/postgresql/tls/server.crt \
  -c ssl_key_file=/var/run/postgresql/tls/server.key \
  -c ssl_ca_file=/var/run/postgresql/tls/ca.crt \
  -c hba_file=/etc/zt/pg_hba.conf \
  -c password_encryption=scram-sha-256 \
  -c log_connections=on \
  -c log_disconnections=on
