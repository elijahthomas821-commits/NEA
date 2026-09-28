"""Application error hierarchy.

Services raise these; the API layer maps them to a consistent JSON error envelope and the
Telegram layer maps them to short user-facing messages. Messages must never contain secrets.
"""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base class for expected, user-presentable failures."""

    code: str = "app_error"
    status_code: int = 400

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFoundError(AppError):
    code = "not_found"
    status_code = 404


class ValidationFailedError(AppError):
    code = "validation_failed"
    status_code = 422


class ConflictError(AppError):
    code = "conflict"
    status_code = 409


class AuthenticationError(AppError):
    code = "unauthenticated"
    status_code = 401


class PermissionDeniedError(AppError):
    code = "forbidden"
    status_code = 403


class InvalidStateError(AppError):
    """An operation is not allowed in the entity's current state (e.g. selling a sold item)."""

    code = "invalid_state"
    status_code = 409


class ExternalServiceError(AppError):
    """An external dependency (Telegram, AI provider) failed."""

    code = "external_service_error"
    status_code = 502


class BudgetExceededError(AppError):
    code = "budget_exceeded"
    status_code = 429
