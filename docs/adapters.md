# Writing a data adapter

Everything that brings data **in** lives in `app/collectors/`. Two kinds of adapter plug into
the rest of the system:

| Protocol | Brings in | Used by |
| --- | --- | --- |
| `MarketplaceAdapter` | listings for sale (`RawListing`) | ingestion → evaluation |
| `MarketDataSource` | completed sales (`RawSale`) | market data → pricing |

Both are defined in `app/collectors/base.py`, with the data they return. Adapters return plain,
validated DTOs; they never touch the database, and the rest of the system never touches an
external source directly.

## Ground rules (read these first)

1. **Only permitted access.** Use an official API you are authorised to use, a licensed data
   feed, or data you export yourself. Do not scrape websites, call private or undocumented app
   endpoints, or get around rate limits, logins, CAPTCHAs or other anti-automation measures.
   Vinted in particular is intake-by-hand only (see the README): `collectors/vinted/` only
   *parses* links you paste; it has no network client.
2. **Declare what you are.** Every adapter publishes `AdapterCapabilities`, including
   `automated` (does it fetch anything by itself?), `max_requests_per_minute`, and
   `terms_reference` (where the terms that permit this access are).
3. **Stop on refusal.** Map 401/403/CAPTCHA/challenge responses to `AccessDeniedError`. The
   resilience wrapper then **disables** the adapter; nothing is retried or bypassed.
4. **Completed sales only** from a `MarketDataSource`. An asking price of an unsold item is not
   a sale. (The one exception is built in: a listing *you* watched that sold keeps its last
   asking price as `last_asking_price`, which pricing discounts and trusts less.)
5. **No secrets in code or the database.** Credentials come from environment settings and are
   registered with the log redactor (`Settings.register_secrets`).

## The data you return

`RawListing` — one listing: `marketplace`, `external_id` (stable ID on that marketplace — the
duplicate guard is `UNIQUE (marketplace, external_id)`), `title`, and whatever else you have:
`url`, `description`, `raw_brand`, `raw_category`, `raw_size`, `raw_colour`, `raw_condition`
(the marketplace's own words: normalisation happens later), `price` + `currency`, `listed_at`,
`status`, `seller` (`RawSeller`), and `extra` for anything else worth keeping.

`RawSale` — one completed sale: `source` (`SaleSource`), `source_ref` (stable ID so the same sale
is never recorded twice), `brand` and `category` (slug, name or alias), optional `product`,
`size`, `colour`, `condition`, `sale_price` + `currency`, `price_type`, `sold_at`, optional
`listed_at` (enables sale-speed estimates).

Money is `Decimal` with two decimal places, never `float`. Timestamps are timezone-aware.

## Errors

Raise the errors from `app/collectors/base.py` so the wrapper can react correctly:

| Error | Meaning | What happens |
| --- | --- | --- |
| `TransientError` | timeout, 5xx, connection reset | retried with exponential backoff and jitter |
| `RateLimitedError(retry_after)` | 429 | waits exactly `retry_after`, then retries |
| `AccessDeniedError` | 401/403/CAPTCHA | the adapter is disabled; never retried |
| `PayloadInvalidError(raw=...)` | unparseable data | not retried; the payload is kept for inspection |
| `NotSupportedError` | operation not offered | reported to the caller |

## Resilience

Wrap your adapter in `ResilientAdapter` (`app/collectors/resilience.py`): a token-bucket rate
limiter (set from `max_requests_per_minute`), a retry policy, and a circuit breaker that stops
calling a failing source for a cool-down period.

## Registering

```python
from app.collectors.registry import register_adapter

register_adapter("mymarket", lambda: ResilientAdapter(MyMarketAdapter(settings)))
```

Add the marketplace code to the `marketplaces` table (seed data or a migration) so listings and
sales can reference it.

## Testing: the contract suite

`tests/unit/test_adapters.py` runs every adapter through the same contract: capabilities and
terms are declared, `health_check` works, search and lookup behave as the capabilities say, and
manual sources are never automated. Add your adapter to the `ADAPTERS` list there. Test HTTP with
`respx` (never the real service), including timeouts, 429, 403 and malformed payloads.

## Checklist

- [ ] The terms that permit this access are linked in `terms_reference`.
- [ ] `automated` and `max_requests_per_minute` are honest.
- [ ] 401/403/CAPTCHA → `AccessDeniedError`; 429 → `RateLimitedError`.
- [ ] Money as `Decimal`, times timezone-aware, stable `external_id` / `source_ref`.
- [ ] Credentials from settings, registered for redaction; no URLs with tokens in logs.
- [ ] Added to the contract suite; HTTP mocked in tests.
