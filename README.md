# Resale sourcing & profit analysis

A single-operator tool for evaluating second-hand clothing listings (Vinted UK) before you buy
them: it identifies the item, prices it from comparable sales, works out fees, profit, ROI and a
maximum purchase price, assesses counterfeit risk, and sends the result to you on Telegram. You
make every purchase yourself — the system never buys anything.

> **Listing intake is manual.** You share or paste listings into the Telegram bot or the API.
> Nothing scrapes Vinted or calls its private endpoints.

## Status

Built in phases (see the architecture plan). Implemented so far:

- **Phase 1 – Foundation:** configuration (environment + versioned business rules), structured
  logging with secret redaction, the full PostgreSQL schema with Alembic migrations, seed data
  (5 brands, 3 in-scope categories, product catalogue, default rules), API skeleton with API-key
  auth and rate limiting, Celery skeleton, Docker Compose and CI.

## Quick start (Docker Compose)

```bash
cp .env.example .env        # set POSTGRES_PASSWORD, TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_USER_IDS
docker compose up -d --build
docker compose run --rm api resale create-user me --telegram-id <your Telegram user id>
docker compose run --rm api resale create-api-key me   # prints the key once
curl -H "Authorization: Bearer <key>" http://127.0.0.1:8000/health
```

The `migrate` service runs `alembic upgrade head` and `resale seed` on every start (both are
idempotent).

## Development

Requires Python 3.12, [uv](https://docs.astral.sh/uv/), PostgreSQL 16 and Redis 7.

```bash
uv sync
export TEST_DATABASE_URL=postgresql+psycopg://resale:resale@127.0.0.1:5432/resale_test
uv run pytest                  # unit + integration tests (real PostgreSQL)
uv run ruff check . && uv run ruff format --check .
uv run mypy app
```

Configuration you will want to review before relying on results:

| Config | Why |
| --- | --- |
| `fees` | Vinted Buyer Protection fee and postage are **placeholders** — verify them. |
| `deal_rules` | Minimum profit/ROI and other thresholds are **placeholders**. |
| `price_guide` | Empty. You have no sales data yet; see "Getting market data" below. |

`resale config show <kind>` prints the active version; `resale config set <kind> file.yaml`
creates a new version (old versions are kept so past evaluations stay reproducible).

## Getting market data

Prices come only from completed sales (comps). With no sales history, evaluations are rejected
with `INSUFFICIENT_MARKET_DATA` until you record some. Options, best first:

1. Your own sales — recorded automatically when you mark an item sold.
2. Sales you research by hand (e.g. sold listings you can see on Vinted or eBay).
3. Your own reference price ranges in the `price_guide` config — used only as a last resort,
   clearly labelled, and capped at REVIEW tier.

## Legacy code

`FlaskProject/` is an unrelated earlier project, left untouched and excluded from lint, type
checks and tests. **It contains credentials committed to git history** (a football-data.org API
key and MySQL credentials). Removing them from the files does not remove them from history —
rotate the API key and change the database password.
