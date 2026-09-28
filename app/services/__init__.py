"""Orchestration services: load data, call pure analysis code, persist results.

Services receive a SQLAlchemy ``Session`` and flush but do not commit; the caller (API request,
Celery task, bot handler, CLI command) owns the transaction.
"""
