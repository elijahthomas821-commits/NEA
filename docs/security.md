# Security review

Scope: the platform in `app/` as deployed with `docker-compose.yml` for a single operator.
`FlaskProject/` is out of scope (see "Open items"). Reviewed 2026-09-28, after Phase 8.

## What is protected, and how

| Area | Control | Checked by |
| --- | --- | --- |
| API access | Every route except `/health`, `/health/ready` and the Telegram webhook requires an API key. Keys are random 256-bit tokens, stored only as SHA-256 hashes, revocable, optionally expiring. | `tests/integration/test_security.py` (sweeps every route), `test_users_and_auth.py` |
| Abuse | Per-key rate limit (Redis); request bodies over `MAX_REQUEST_BYTES` refused before parsing; upload and image size limits; image pixel limit (decompression bombs). | `test_security.py`, `test_images_and_csv.py` |
| Telegram | Only allowlisted user IDs are served; everyone else is ignored (except `/start`, which tells a stranger their own ID). Webhook mode checks Telegram's secret header with a constant-time comparison; the secret must be 16+ characters. Callback data is parsed strictly. | `test_telegram_handlers.py`, `test_telegram_runner.py` |
| Secrets | Only in the environment, never in the database or code. Registered with the log redactor; Bot API URLs (which contain the token) are never logged and HTTP errors are not chained. Secret scanning (gitleaks) runs in CI. | `test_redaction.py`, `test_telegram_client.py` |
| Outbound network | Only two modules make network calls: the Telegram client and the Anthropic provider. Nothing fetches marketplace pages or arbitrary URLs, so there is no scraping and no server-side request forgery surface. Photos are uploaded by you (API or Telegram); Telegram file paths are validated and downloads are size-capped. | `tests/unit/test_architecture.py` |
| Injection | SQL only through SQLAlchemy with bound parameters (`text()` only ever gets literal SQL). All text in Telegram messages is HTML-escaped; links are rendered only for `http(s)`. CSV exports prefix formula-like cells with `'`. No `eval`/`exec`, pickle, shell commands or unsafe YAML. | `test_architecture.py`, `test_telegram_formatter.py`, `test_api_inventory.py` |
| Errors | Unexpected errors return a generic 500 with a request ID; details go only to the (redacted) log. | `test_security.py` |
| Money records | Purchases, resales, inventory changes and configuration changes are written to the audit log; database CHECK constraints keep totals consistent (and caught a real bug during development). | integration tests |
| AI | Optional, budget-capped, strict response schema with no money fields; AI output never enters a money calculation. Listing text and photos you add are sent to Anthropic when AI is enabled. | `test_ai_and_identification.py` |
| Containers | Non-root user, read-only root filesystem, no Linux capabilities, `no-new-privileges`; database and Redis not exposed outside the Docker network; API bound to 127.0.0.1. | CI smoke test runs the image with these restrictions |
| Dependencies | `pip-audit --strict` in CI (no known vulnerabilities at review time); locked with `uv.lock`. | CI |
| Purchases | The system never buys anything: BUY only records your intent. | design |

## Open items and residual risks

1. **Committed credentials in `FlaskProject/` git history** (a football-data.org API key, MySQL
   credentials for `ND-COMPSCI`, a Flask secret key). Deleting the files does not remove them from
   history. **Rotate the API key and change the database password.** Purging history needs a
   force-push, so it is left to you.
2. **Redis has no password.** It is reachable only inside the Compose network. If you expose it or
   run it elsewhere, set a password and use it in `REDIS_URL`.
3. **One API key scope.** All keys have full access (single operator). Keep keys off shared
   machines and revoke any you no longer use.
4. **Webhook mode needs HTTPS in front of the API** (a reverse proxy with TLS). Polling mode, the
   default, needs no inbound access at all.
5. **AI data sharing.** With AI enabled, listing text and the photos you attach are sent to
   Anthropic. Leave `ANTHROPIC_API_KEY` empty to run rules-only.
6. **Placeholder business rules.** Fees and thresholds are placeholders; wrong values produce
   wrong recommendations (not a security issue, but a financial one).
