# Configuration reference

There are two kinds of configuration, kept apart on purpose:

| | Where | Changed by | Examples |
| --- | --- | --- | --- |
| **Environment settings** | `.env` / environment variables | editing `.env`, restarting | database URL, Telegram token, AI key and budget |
| **Business rules** | the `config_versions` table (versioned) | `resale config set`, `PUT /config/{kind}` | fees, profit thresholds, comp weights |

Secrets only ever live in the environment, never in the database. Business rules are versioned
so every evaluation records the exact versions it used and can be reproduced later.

## Environment settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_ENV` | `dev` | `dev`, `test` or `prod` |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `json` | `json` in production, `console` for local reading |
| `POSTGRES_PASSWORD` | — | compose only: the bundled database's password |
| `DATABASE_URL` | local | `postgresql+psycopg://user:password@host:5432/db` (set by compose) |
| `DATABASE_POOL_SIZE` | 5 | connections per process |
| `REDIS_URL` | local | Celery broker and API rate limits (set by compose) |
| `BASE_CURRENCY` | `GBP` | your business currency; analytics and deal rules use it |
| `DISPLAY_TIMEZONE` | `Europe/London` | for display |
| `DEFAULT_MARKETPLACE` | `vinted` | for listings sent without a recognisable link |
| `MEDIA_DIR` | `./media` | uploaded listing photos (compose: the `media` volume) |
| `MAX_IMAGE_BYTES` | 8 MB | largest photo accepted |
| `MAX_IMAGES_PER_LISTING` | 12 | |
| `MAX_UPLOAD_BYTES` | 5 MB | largest CSV import |
| `MAX_REQUEST_BYTES` | 64 MB | requests larger than this are refused before parsing |
| `API_RATE_LIMIT_PER_MINUTE` | 120 | per API key |
| `API_DOCS_ENABLED` | true | `/docs` and `/openapi.json` |
| `TELEGRAM_BOT_TOKEN` | — | from @BotFather; without it the bot and alerts are off |
| `TELEGRAM_ALLOWED_USER_IDS` | — | comma-separated Telegram user IDs; everyone else is ignored |
| `TELEGRAM_ALERT_CHAT_ID` | first allowed user | where alerts go |
| `TELEGRAM_MODE` | `polling` | or `webhook` (needs the two below) |
| `TELEGRAM_WEBHOOK_URL` | — | `https://…/telegram/webhook` |
| `TELEGRAM_WEBHOOK_SECRET` | — | 16–256 of `A-Z a-z 0-9 _ -`; checked on every webhook call |
| `TELEGRAM_POLL_TIMEOUT_SECONDS` | 30 | long-poll length |
| `AI_ENABLED` | true | AI is used only if this is true **and** a key is set |
| `ANTHROPIC_API_KEY` | — | leave empty to run rules-only |
| `AI_MODEL` | `claude-opus-5` | |
| `AI_EFFORT` | `low` | `low`, `medium` or `high` |
| `AI_DAILY_BUDGET_USD` / `AI_MONTHLY_BUDGET_USD` | 1.00 / 10.00 | hard caps; over budget → rules-only |
| `AI_MAX_IMAGES` | 6 | photos sent per analysis |
| `AI_TIMEOUT_SECONDS` | 60 | |

## Business rules

View and change them with the CLI or the API:

```bash
resale config show deal_rules          # active version as YAML
resale config set deal_rules my.yaml   # new version (validated; old versions kept)
resale config history deal_rules
```

`GET /config`, `GET /config/{kind}`, `PUT /config/{kind}`, `GET /config/{kind}/versions`,
`POST /config/{kind}/versions/{version}/activate` do the same over the API. Every change is
validated against a strict schema (unknown keys are rejected) and written to the audit log.
The defaults, with comments, are in `app/config/defaults/*.yaml`.

**Placeholders.** The fee amounts and the profit thresholds are placeholders. Check the fees
against Vinted's current Buyer Protection fee and postage, and set thresholds you are
comfortable with, before relying on the results.

| Kind | What it controls | Main fields |
| --- | --- | --- |
| `fees` | buying and selling costs per channel | `purchase_channels` (buyer fee rule, default postage), `selling_channels` (selling fee, postage you pay, packaging, expected refund rate), default cleaning/repair/other costs, `values_verified_on` |
| `deal_rules` | when a listing is worth buying | `min_profit`, `min_roi`, `max_median_sale_days`, `min_product_confidence`, `min_authenticity_confidence`, `max_authenticity_risk`, `max_purchase_price`, `max_capital_per_item`, `max_inventory_exposure`, `max_units_per_product`, `exclude_kids_sizes`, `low_auth_confidence_action`, `high_priority` (stricter tier), `review` (near misses), `caps`, `realert` (price-drop thresholds for repeat alerts) |
| `market` | comparable sales | `window_days`, `half_life_days`, `min_sample_size`, `min_effective_n`, fallback `levels`, `estimate_percentiles`, `source_trust`, `marketplace_trust`, `last_asking_price` (haircut and trust), `outliers`, `confidence`, `fx_max_age_days`, `velocity`, `price_guide` |
| `conditions` | condition adjustments | `multipliers` per condition, `assume_when_unknown` |
| `sizes` | size adjustments and numeric size systems | `multipliers`, `numeric_systems`, `brand_numeric_system` |
| `authenticity` | counterfeit-risk model | `low_risk_below`, `high_risk_from`, log-odds `shifts`, price-anomaly ratios, seller thresholds, `brand_checklists`, recommended checks |
| `identification` | brand/category/product identification | confidences per evidence source, replica phrases, `ai` (when to ask the AI), `mislabel`, `matching` thresholds |
| `price_guide` | your own reference prices (last resort) | `entries`: brand, category, optional product/condition/size, `low` / `typical` / `high` |

The catalogue (brands, categories, products and their aliases) is data, managed through
`/brands`, `/categories` and `/products` (seeded from `app/config/defaults/`).

How every number is calculated from these rules is in
[financial-calculations.md](financial-calculations.md).
