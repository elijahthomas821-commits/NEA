# Resale sourcing & profit analysis

A single-operator tool for evaluating second-hand clothing listings (Vinted UK) before you buy
them: it identifies the item, prices it from comparable sales, works out fees, profit, ROI and a
maximum purchase price, assesses counterfeit risk, and sends the result to you on Telegram. You
make every purchase yourself — the system never buys anything.

> **Listing intake is manual.** You share or paste listings into the Telegram bot or the API.
> Nothing scrapes Vinted or calls its private endpoints.

## Status

Built in phases (see the architecture plan). Implemented so far:

- **Foundation:** configuration (environment + versioned business rules), structured logging
  with secret redaction, PostgreSQL schema with Alembic migrations, seed data, API with API-key
  auth and rate limiting, Celery, Docker Compose and CI.
- **Intake:** listings by Telegram, API (JSON or free text with a Vinted link) and CSV; photo
  uploads; duplicate-safe upserts with price and status history.
- **Identification:** brand/category/size/condition/colour normalisation, product matching,
  optional AI help (Claude) behind a budget, never used for money calculations.
- **Pricing:** comparable sales with fallback levels, recency weights and outlier removal; your
  own price guide as a last resort.
- **Profit:** fees, ROI, maximum purchase price, sale velocity.
- **Decision:** counterfeit-risk assessment (never a verdict), deal rules with reasons, and a
  reproducible snapshot of every evaluation.
- **Telegram:** alerts with BUY / PASS / REVIEW, chat-based listing entry, photos, market data
  entry, purchase recording.
- **Stock and results:** purchases (including bundles, split to the penny), the inventory
  lifecycle, your sales (which feed back into market data and score the original prediction),
  analytics and CSV exports.

Still to come: hardening and full documentation (Phase 9).

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

## Using the Telegram bot

Create a bot with @BotFather, put its token in `TELEGRAM_BOT_TOKEN`, send `/start` to it to
learn your Telegram user ID, and put that in `TELEGRAM_ALLOWED_USER_IDS`. Everyone else is
ignored. The `bot` service uses long polling, so no public URL is needed (set
`TELEGRAM_MODE=webhook` with an HTTPS URL and a secret if you prefer a webhook).

- **Check a listing:** paste the Vinted link with the price, e.g.
  `https://www.vinted.co.uk/items/123-stone-island-crewneck £45`. The result arrives a few
  seconds later. Anything you add (size, condition) helps identification.
- **Photos:** send photos of labels, badges and tags after the link (or with the link as the
  caption), then tap *Evaluate now*. They improve the counterfeit-risk check.
- **Step by step:** `/add` asks for the link, price, brand, size, condition and photos.
- **Decisions:** alerts have BUY / PASS / REVIEW buttons. BUY only records your decision; buy the
  item yourself, then reply with what you paid to record the purchase.
- **Keeping listings current:** `/price 12 £40`, `/sold 12` (sold to someone else), `/gone 12`,
  `/check 12`, `/show 12`, `/recent`.

Alerts go to your private chat (or `TELEGRAM_ALERT_CHAT_ID`; keep the private chat if you can,
because in groups Telegram hides ordinary replies from bots). Listings you send always get a
reply, including "not a deal"; bulk CSV imports only message you about listings worth a look,
and a listing is only re-sent when its decision improves or its price drops materially.

## Tracking stock and results

After you buy something (BUY in Telegram, or `POST /purchases` for bundles), it is an item in
your stock. Move it along with `/received 7`, `/listed 7 £99`, `/sale 7 £95`, `/shipped 7`,
`/done 7` (or `/writeoff 7`), and see `/stock`, `/item 7` and `/stats`; the API has the same
under `/inventory`, `/resales` and `/analytics` (summary, breakdowns, prediction accuracy,
funnel, CSV exports). Every figure is defined in [docs/analytics.md](docs/analytics.md) and the
money rules are in [docs/financial-calculations.md](docs/financial-calculations.md).

## Getting market data

Prices come only from completed sales (comps). With no sales history, evaluations are rejected
with `INSUFFICIENT_MARKET_DATA` until you record some. Options, best first:

1. Your own sales — recorded automatically when you mark an item sold.
2. Sales you research by hand (e.g. sold listings you can see on Vinted or eBay): `/comp` in
   Telegram, `POST /market/sales`, or a CSV import.
3. Listings you were watching that sold to someone else: `/sold 12` keeps the last asking price
   as a weaker data point (discounted, and trusted less than a real sale price).
4. Your own reference price ranges in the `price_guide` config — used only as a last resort,
   clearly labelled, and capped at REVIEW tier.

## Legacy code

`FlaskProject/` is an unrelated earlier project, left untouched and excluded from lint, type
checks and tests. **It contains credentials committed to git history** (a football-data.org API
key and MySQL credentials). Removing them from the files does not remove them from history —
rotate the API key and change the database password.
