"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app import __version__
from app.api.errors import install_error_handlers
from app.api.ratelimit import InMemoryRateLimiter, RateLimiter, RedisRateLimiter
from app.config.settings import Settings, get_settings
from app.core.ids import clean_correlation_id
from app.core.logging import bind_correlation_id, clear_context, configure_logging
from app.database.session import Database, get_database
from app.workers.dispatch import CeleryDispatcher, TaskDispatcher


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    dispatcher: TaskDispatcher | None = None,
    rate_limiter: RateLimiter | None = None,
    configure_logs: bool = True,
) -> FastAPI:
    settings = settings or get_settings()
    settings.register_secrets()
    if configure_logs:
        configure_logging(settings.log_level, settings.log_format)

    app = FastAPI(
        title="Resale sourcing & profit analysis",
        version=__version__,
        docs_url="/docs" if settings.api_docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.api_docs_enabled else None,
    )
    app.state.settings = settings
    app.state.database = database or get_database()
    app.state.dispatcher = dispatcher or CeleryDispatcher()
    redis_url = settings.redis_url.get_secret_value()
    app.state.rate_limiter = rate_limiter or RedisRateLimiter(redis_url)
    app.state.redis_probe = _redis_probe(redis_url) if rate_limiter is None else None

    install_error_handlers(app)

    @app.middleware("http")
    async def correlation_and_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        declared = request.headers.get("content-length")
        limit = request.app.state.settings.max_request_bytes
        if declared and declared.isdigit() and int(declared) > limit:
            return JSONResponse(
                status_code=413,
                content={"error": {"code": "payload_too_large", "message": "request too large"}},
            )
        correlation_id = clean_correlation_id(request.headers.get("x-request-id"))
        request.state.correlation_id = correlation_id
        clear_context()
        bind_correlation_id(correlation_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    from app.api.routes import catalogue, config, health, imports, listings, market

    for router in (
        health.router,
        listings.router,
        imports.router,
        catalogue.router,
        market.router,
        config.router,
    ):
        app.include_router(router)
    return app


def _redis_probe(url: str) -> Callable[[], None]:
    def probe() -> None:
        import redis

        client = redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
        try:
            client.ping()
        finally:
            client.close()

    return probe


def app_factory() -> FastAPI:
    """Entry point for ``uvicorn --factory app.main:app_factory``."""
    return create_app()


__all__ = ["InMemoryRateLimiter", "app_factory", "create_app"]
