"""Optional AI assistance (identification, photo checks).

Guarantees, enforced here and in the schemas:

* AI output is parsed into strict schemas that contain **no price or money fields** — nothing an
  AI returns can reach a profit calculation.
* Brands and categories must be catalogue slugs (or "unknown"); anything else is discarded.
* AI-derived confidence is capped by configuration.
* Every call is recorded (cost, tokens, outcome); daily and monthly budgets are enforced before
  a call is made; identical requests are answered from the cache.
* Failures degrade to rules-only identification, which lowers confidence and so blocks the
  high-priority tier — they never crash an evaluation.
"""
