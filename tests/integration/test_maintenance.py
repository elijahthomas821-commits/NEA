from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.time import utcnow
from app.models import BotState
from app.workers.tasks.maintenance import prune_expired_state

pytestmark = pytest.mark.integration


def test_prune_expired_state(db_session):
    now = utcnow()
    db_session.add_all(
        [
            BotState(key="old", value={}, expires_at=now - timedelta(hours=1)),
            BotState(key="fresh", value={}, expires_at=now + timedelta(hours=1)),
            BotState(key="forever", value={}, expires_at=None),
        ]
    )
    db_session.flush()
    assert prune_expired_state(db_session) == 1
    keys = set(db_session.scalars(select(BotState.key)))
    assert keys == {"fresh", "forever"}
