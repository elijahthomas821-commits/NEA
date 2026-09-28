# Runbook

How to run, update, back up and troubleshoot the system on a single host with Docker Compose.

## What runs

| Service | Does | Notes |
| --- | --- | --- |
| `postgres` | the database | data in the `pgdata` volume; not exposed outside Docker |
| `redis` | task queue and API rate limits | data in `redisdata`; not exposed outside Docker |
| `migrate` | `alembic upgrade head` then `resale seed`, then exits | runs before the others on every start; both steps are idempotent |
| `api` | the HTTP API on `127.0.0.1:8000` | bound to localhost only |
| `worker` | evaluations, alerts, market statistics | Celery, 2 processes |
| `beat` | the schedule below | |
| `bot` | the Telegram bot (long polling) | needs no public address |

Schedule (UTC): market statistics 03:17 daily; expired chat state pruned 04:07 daily; alerts
stuck in `pending` re-queued every 15 minutes (and given up after two days).

The app containers run as a non-root user with a read-only filesystem, no Linux capabilities
and `no-new-privileges`; only the `media` volume (listing photos) and `/tmp` are writable.

## First start

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD (long and random) and TELEGRAM_BOT_TOKEN (from @BotFather).
docker compose up -d --build
docker compose run --rm api resale create-user me
docker compose run --rm api resale create-api-key me     # shown once: store it safely
```

Then send `/start` to your bot: it replies with your Telegram user ID. Put it in `.env`
(`TELEGRAM_ALLOWED_USER_IDS=...`) and restart the bot with `docker compose up -d bot`. The bot
creates its own user record on your first message (or pass `--telegram-id <id>` to
`create-user` to use the same user for the API and the bot).

Before relying on results: review the placeholder fees and deal thresholds
(`resale config show fees`, `resale config show deal_rules`) and record some market data (see
the README).

## Updating

```bash
git pull
docker compose up -d --build     # migrate runs first; the others wait for it
```

Database changes are Alembic migrations applied by `migrate`. To check where a database is:
`docker compose run --rm api alembic current`.

## Backups

The database holds everything except the photos, which live in the `media` volume.

```bash
# Database (custom format, compressed)
docker compose exec -T postgres pg_dump -U resale -Fc resale > backup-$(date +%F).dump
# Photos
docker run --rm -v resale_media:/media -v "$PWD":/out alpine \
    tar czf /out/media-$(date +%F).tar.gz -C /media .
```

Keep copies off the machine, and test a restore now and then.

**Restore** (stops writes first):

```bash
docker compose stop api worker beat bot
docker compose exec -T postgres pg_restore -U resale -d resale --clean --if-exists < backup.dump
docker run --rm -v resale_media:/media -v "$PWD":/in alpine tar xzf /in/media.tar.gz -C /media
docker compose up -d
```

## Rotating secrets

| Secret | How |
| --- | --- |
| Telegram bot token | @BotFather → `/revoke`, put the new token in `.env`, `docker compose up -d` |
| API key | `resale create-api-key me --name new`, switch your client, then `resale revoke-api-key <old prefix>` |
| Anthropic API key | replace in `.env`, `docker compose up -d` (revoke the old one in the Anthropic console) |
| Webhook secret (webhook mode) | replace in `.env`, `docker compose up -d`, then `docker compose run --rm api resale bot` re-registers it |
| Database password | `docker compose exec postgres psql -U resale -c "ALTER USER resale PASSWORD '...'"`, update `POSTGRES_PASSWORD`, `docker compose up -d` |

Secrets are never stored in the database and are redacted from logs.

## Monitoring

- **Health:** `GET /health` (process up) and `GET /health/ready` (database and Redis reachable).
- **Logs:** JSON on stdout (`docker compose logs -f worker`); every request and task carries a
  `correlation_id`. Tokens, keys and passwords are redacted.
- **Failed background tasks** are recorded in `task_failures` after their retries run out:
  ```bash
  docker compose exec postgres psql -U resale -c \
    "SELECT failed_at, task_name, error FROM task_failures WHERE resolved_at IS NULL ORDER BY failed_at DESC LIMIT 20"
  ```
- **Alerts that could not be sent:** `GET /alerts?status=failed` (`last_error` says why, e.g.
  the bot was blocked or the chat ID is wrong).
- **AI spend:** `GET /analytics/funnel` (`ai_requests`, `ai_cost_usd`). The daily and monthly
  budgets are hard caps: when reached, evaluations continue rules-only.

## After changing rules or adding market data

Evaluations are snapshots: changing fees, thresholds or comps does not rewrite past results.
To re-check the listings that are still active:

```bash
docker compose run --rm api resale reevaluate --seen-within-days 14
```

Only listings that became worth a look (or improved, or dropped in price materially) message
you. Every evaluation records the configuration versions it used, so older results stay
explainable.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| The bot doesn't answer | Token missing or revoked (bot logs `telegram_token_rejected`); your ID not in `TELEGRAM_ALLOWED_USER_IDS`; the `bot` service stopped. `/start` from an unlisted account replies with that account's ID. |
| `Conflict: terminated by other getUpdates request` | Two bots polling with the same token, or a webhook is set. Run one `bot` service; polling mode deletes the webhook on start. |
| Alerts don't arrive | `GET /alerts?status=failed`; check `TELEGRAM_ALERT_CHAT_ID`, and that you've sent the bot a message (bots can't start a chat). |
| Every listing is "not a deal: insufficient market data" | No comparable sales for that brand and category yet: record some (`/comp`, `POST /market/sales`, CSV import). |
| "AI unavailable" limits | No key, `AI_ENABLED=false`, or the budget is used up. Results are capped rather than guessed. |
| API returns 429 | Rate limit per key (`API_RATE_LIMIT_PER_MINUTE`). |
| `migrate` fails | `docker compose logs migrate`; the others don't start until it succeeds. |

## Performance

`scripts/perf_benchmark.py` seeds a separate database at the planned scale (500 000 listings,
100 000 sales) and measures. On the development machine (2026-09):

| Measure | Result |
| --- | --- |
| Comparable-sales query, ~3 300 comps per brand × category | p50 21 ms, p95 34 ms (target < 50 ms) |
| …including building the comp objects | p50 32 ms, p95 67 ms |
| Sale-velocity lookup | p50 105 ms |
| Full evaluation (rules only, no AI) | ~340 ms each, ~3 per second |

Run it against a throw-away database only (it drops and recreates the schema):
`uv run python scripts/perf_benchmark.py --database-url postgresql+psycopg://…/resale_perf`.
A lighter version runs in CI (`tests/integration/test_performance.py`).
