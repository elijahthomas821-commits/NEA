"""Command-line entry point: ``resale <command>`` (or ``python -m app.cli``)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.config.settings import get_settings
from app.core.enums import ConfigKind
from app.core.logging import configure_logging
from app.database.session import get_database
from app.workers.dispatch import TaskDispatcher


def _cmd_seed(args: argparse.Namespace) -> int:
    from app.services.seed import seed_reference_data

    with get_database().session_scope() as session:
        report = seed_reference_data(session, update_config=args.update_config)
    print(json.dumps({"created": report.created, "warnings": report.warnings}, indent=2))
    return 0


def _cmd_create_user(args: argparse.Namespace) -> int:
    from app.services.users import create_user

    with get_database().session_scope() as session:
        user = create_user(session, args.username, telegram_user_id=args.telegram_id)
        print(f"created user {user.username} (id {user.id})")
    return 0


def _cmd_create_api_key(args: argparse.Namespace) -> int:
    from app.services.users import create_api_key, get_user_by_username

    with get_database().session_scope() as session:
        user = get_user_by_username(session, args.username)
        plaintext, key = create_api_key(
            session, user, name=args.name, expires_in_days=args.expires_days
        )
        print("API key (shown once - store it now):")
        print(plaintext)
        print(f"prefix: {key.key_prefix}")
    return 0


def _cmd_revoke_api_key(args: argparse.Namespace) -> int:
    from app.services.users import revoke_api_key

    with get_database().session_scope() as session:
        revoke_api_key(session, args.prefix)
    print("revoked")
    return 0


def _cmd_config_show(args: argparse.Namespace) -> int:
    from app.services.config_service import ConfigService

    with get_database().session_scope() as session:
        row = ConfigService(session).active_row(ConfigKind(args.kind))
        print(
            f"# {row.kind} version {row.version} (id {row.id}, created {row.created_at:%Y-%m-%d})"
        )
        print(yaml.safe_dump(row.payload, sort_keys=False, allow_unicode=True))
    return 0


def _cmd_config_set(args: argparse.Namespace) -> int:
    from app.services.audit import Actor
    from app.services.config_service import ConfigService

    payload = yaml.safe_load(Path(args.file).read_text(encoding="utf-8"))
    with get_database().session_scope() as session:
        row, created = ConfigService(session).create_version(
            ConfigKind(args.kind), payload, actor=Actor.system("cli"), note=args.note
        )
        print(f"{'created' if created else 'unchanged'}: {row.kind} version {row.version}")
    return 0


def _cmd_config_history(args: argparse.Namespace) -> int:
    from app.services.config_service import ConfigService

    with get_database().session_scope() as session:
        for row in ConfigService(session).list_versions(ConfigKind(args.kind)):
            marker = "*" if row.is_active else " "
            print(
                f"{marker} v{row.version:<4} id={row.id:<6} {row.created_at:%Y-%m-%d %H:%M} "
                f"{row.created_by or ''} {row.note or ''}"
            )
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    from app.services.pipeline import evaluate_listing_by_id

    with get_database().session_scope() as session:
        evaluation = evaluate_listing_by_id(session, args.listing_id, trigger="manual")
        print(
            json.dumps(
                {
                    "evaluation_id": evaluation.id,
                    "decision": evaluation.decision,
                    "reason_codes": evaluation.reason_codes,
                    "expected_profit": str(evaluation.expected_profit),
                    "max_purchase_price": str(evaluation.max_purchase_price),
                },
                indent=2,
            )
        )
    return 0


def queue_reevaluation(
    session: Session, dispatcher: TaskDispatcher, *, seen_within_days: int | None
) -> int:
    """Queue every active listing for re-evaluation (after you change the rules or add market
    data). Alerts use the re-alert policy: only listings that became worth a look message you."""
    from sqlalchemy import select

    from app.core.enums import AlertMode, ListingStatus
    from app.core.time import utcnow
    from app.models import Listing

    query = select(Listing.id).where(Listing.status == ListingStatus.ACTIVE.value)
    if seen_within_days is not None:
        query = query.where(Listing.last_seen_at >= utcnow() - timedelta(days=seen_within_days))
    count = 0
    for listing_id in session.scalars(query.order_by(Listing.id)):
        dispatcher.evaluate_listing(listing_id, trigger="config_change", alert=AlertMode.DEALS)
        count += 1
    return count


def _cmd_reevaluate(args: argparse.Namespace) -> int:
    from app.workers.dispatch import CeleryDispatcher

    with get_database().session_scope() as session:
        count = queue_reevaluation(
            session, CeleryDispatcher(), seen_within_days=args.seen_within_days
        )
    print(f"queued {count} active listings for re-evaluation")
    return 0


def _cmd_bot(_args: argparse.Namespace) -> int:
    from app.notifications.telegram.runner import run_bot

    return run_bot()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="resale", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("seed", help="load reference data and default configuration")
    p.add_argument(
        "--update-config",
        action="store_true",
        help="create new config versions from the YAML defaults where they differ",
    )
    p.set_defaults(func=_cmd_seed)

    p = sub.add_parser("create-user", help="create the operator user")
    p.add_argument("username")
    p.add_argument("--telegram-id", type=int, default=None)
    p.set_defaults(func=_cmd_create_user)

    p = sub.add_parser("create-api-key", help="create an API key (printed once)")
    p.add_argument("username")
    p.add_argument("--name", default="default")
    p.add_argument("--expires-days", type=int, default=None)
    p.set_defaults(func=_cmd_create_api_key)

    p = sub.add_parser("revoke-api-key", help="revoke an API key by its prefix")
    p.add_argument("prefix")
    p.set_defaults(func=_cmd_revoke_api_key)

    config = sub.add_parser("config", help="show or change versioned configuration")
    csub = config.add_subparsers(dest="config_command", required=True)
    kinds = [k.value for k in ConfigKind]
    p = csub.add_parser("show")
    p.add_argument("kind", choices=kinds)
    p.set_defaults(func=_cmd_config_show)
    p = csub.add_parser("set")
    p.add_argument("kind", choices=kinds)
    p.add_argument("file", help="YAML file with the full payload")
    p.add_argument("--note", default=None)
    p.set_defaults(func=_cmd_config_set)
    p = csub.add_parser("history")
    p.add_argument("kind", choices=kinds)
    p.set_defaults(func=_cmd_config_history)

    p = sub.add_parser("evaluate", help="evaluate one listing now (synchronously)")
    p.add_argument("listing_id", type=int)
    p.set_defaults(func=_cmd_evaluate)

    p = sub.add_parser(
        "reevaluate", help="re-evaluate active listings (after changing rules or market data)"
    )
    p.add_argument(
        "--seen-within-days", type=int, default=None, help="only listings seen this recently"
    )
    p.set_defaults(func=_cmd_reevaluate)

    p = sub.add_parser(
        "bot", help="run the Telegram bot (long polling), or register the webhook in webhook mode"
    )
    p.set_defaults(func=_cmd_bot)
    return parser


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # CLI boundary: print a clean message, not a traceback
        from app.core.errors import AppError
        from app.core.redaction import redact_text

        if isinstance(exc, AppError):
            print(f"error: {exc.message}", file=sys.stderr)
            if exc.details:
                print(json.dumps(exc.details, indent=2, default=str), file=sys.stderr)
            return 2
        print(f"error: {redact_text(str(exc))}", file=sys.stderr)
        raise


if __name__ == "__main__":
    sys.exit(main())
