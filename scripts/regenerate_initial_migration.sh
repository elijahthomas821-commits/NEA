#!/usr/bin/env bash
# Development helper: rebuild migrations/versions/0001_initial_schema.py from the models.
# Only valid while nothing has been deployed. Once a database exists in production, add new
# migrations with `alembic revision --autogenerate` instead.
set -euo pipefail

DB_URL="${SCRATCH_DATABASE_URL:-postgresql+psycopg://resale:resale@127.0.0.1:5432/resale}"
cd "$(dirname "$0")/.."

psql "${DB_URL/postgresql+psycopg/postgresql}" -q -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
rm -f migrations/versions/0001_initial_schema.py
DATABASE_URL="$DB_URL" uv run alembic revision --autogenerate -m "initial schema" --rev-id 0001_initial >/dev/null
generated=$(ls migrations/versions/*_0001_initial_initial_schema.py)
mv "$generated" migrations/versions/0001_initial_schema.py
DATABASE_URL="$DB_URL" uv run alembic upgrade head >/dev/null
DATABASE_URL="$DB_URL" uv run alembic check
