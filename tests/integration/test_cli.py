"""The ``resale`` command line."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app import cli
from app.models import ApiKey, User
from app.services.ingestion import update_listing
from app.workers.dispatch import RecordingDispatcher
from tests.factories import NOW
from tests.integration.test_pipeline import listing_for

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def quiet_logging(monkeypatch):
    monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: None)


def test_users_and_keys(test_db, db_session, capsys):
    assert cli.main(["create-user", "me", "--telegram-id", "4242"]) == 0
    assert "created user me" in capsys.readouterr().out
    assert cli.main(["create-api-key", "me", "--name", "laptop"]) == 0
    out = capsys.readouterr().out
    plaintext = out.splitlines()[1]
    assert plaintext.startswith("rsk_")
    key = db_session.scalar(select(ApiKey).where(ApiKey.name == "laptop"))
    assert plaintext not in {key.key_hash, key.key_prefix}  # only a hash is stored
    assert cli.main(["revoke-api-key", key.key_prefix]) == 0
    db_session.expire_all()
    assert db_session.get(ApiKey, key.id).revoked_at is not None
    assert db_session.scalar(select(User).where(User.username == "me")).telegram_user_id == 4242


def test_errors_are_reported_cleanly(test_db, capsys):
    assert cli.main(["create-api-key", "nobody"]) == 2
    assert "error: user 'nobody' not found" in capsys.readouterr().err


def test_config_show_set_history(test_db, tmp_path, capsys):
    assert cli.main(["config", "show", "deal_rules"]) == 0
    shown = capsys.readouterr().out
    assert shown.startswith("# deal_rules version 1")
    assert "min_profit" in shown
    changed = tmp_path / "rules.yaml"
    import yaml

    payload = yaml.safe_load(shown)
    payload["min_profit"] = "30.00"
    changed.write_text(yaml.safe_dump(payload), encoding="utf-8")
    assert cli.main(["config", "set", "deal_rules", str(changed), "--note", "stricter"]) == 0
    assert "created: deal_rules version 2" in capsys.readouterr().out
    assert cli.main(["config", "history", "deal_rules"]) == 0
    history = capsys.readouterr().out.splitlines()
    assert history[0].startswith("* v2")


def test_evaluate(test_db, db_session, capsys):
    listing = listing_for(db_session)
    db_session.commit()
    assert cli.main(["evaluate", str(listing.id)]) == 0
    assert '"decision": "rejected"' in capsys.readouterr().out  # no market data yet


def test_reevaluate_queues_active_listings(db_session):
    active = listing_for(db_session)
    gone = listing_for(db_session)
    from app.core.enums import ListingStatus

    update_listing(db_session, gone.id, now=NOW, status=ListingStatus.REMOVED)
    dispatcher = RecordingDispatcher()
    count = cli.queue_reevaluation(db_session, dispatcher, seen_within_days=None)
    assert count == 1
    assert dispatcher.calls == [
        (
            "evaluate_listing",
            {"listing_id": active.id, "trigger": "config_change", "alert": "deals"},
        )
    ]
    assert cli.queue_reevaluation(db_session, RecordingDispatcher(), seen_within_days=1) == 0


def test_reevaluate_command(test_db, monkeypatch, capsys):
    recorder = RecordingDispatcher()
    monkeypatch.setattr("app.workers.dispatch.CeleryDispatcher", lambda: recorder)
    assert cli.main(["reevaluate"]) == 0
    assert "queued 0 active listings" in capsys.readouterr().out


def test_bot_without_token(test_db, monkeypatch):
    monkeypatch.setattr("app.notifications.telegram.runner.configure_logging", lambda *a, **k: None)
    assert cli.main(["bot"]) == 2
