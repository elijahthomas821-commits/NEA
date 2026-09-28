from __future__ import annotations

import pytest

from app.workers.dispatch import InlineDispatcher
from app.workers.tasks.evaluate import run_evaluation

pytestmark = pytest.mark.integration

LINK = "https://www.vinted.co.uk/items/4829301234-stone-island-garment-dyed-crewneck-sweatshirt"


def test_evaluate_now_and_read_back(auth_client):
    listing = auth_client.post(
        "/listings", json={"url": LINK, "price": "45.00", "size": "L", "brand": "Stone Island"}
    ).json()["listing"]
    response = auth_client.post(f"/listings/{listing['id']}/evaluate")
    assert response.status_code == 200, response.text
    evaluation = response.json()["evaluation"]
    assert evaluation["decision"] == "rejected"
    assert "INSUFFICIENT_MARKET_DATA" in evaluation["reason_codes"]

    history = auth_client.get(f"/listings/{listing['id']}/evaluations").json()
    assert [e["id"] for e in history] == [evaluation["id"]]
    detail = auth_client.get(f"/evaluations/{evaluation['id']}").json()
    assert detail["details"]["identification"]["brand_slug"] == "stone-island"
    assert detail["pipeline_version"]


def test_async_evaluate_queues(auth_client, dispatcher):
    listing = auth_client.post("/listings", json={"title": "Moncler Maya", "price": "200"}).json()[
        "listing"
    ]
    dispatcher.calls.clear()
    assert auth_client.post(
        f"/listings/{listing['id']}/evaluate", params={"sync": False}
    ).json() == {"queued": True}
    assert dispatcher.calls == [
        ("evaluate_listing", {"listing_id": listing["id"], "trigger": "manual", "alert": "off"})
    ]


def test_missing_things(auth_client):
    assert auth_client.post("/listings/999999/evaluate").status_code == 404
    assert auth_client.get("/evaluations/999999").status_code == 404
    assert auth_client.get("/listings/999999/evaluations").status_code == 404


def test_inline_dispatcher_runs_the_task_body(app, auth_client, test_db):
    notified: list[int] = []

    def notify(*, evaluation_id: int, alert: str) -> None:
        assert alert == "always"
        notified.append(evaluation_id)

    app.state.dispatcher = InlineDispatcher(evaluate=run_evaluation, notify=notify)
    body = auth_client.post("/listings", json={"url": LINK, "price": "45.00"}).json()
    assert body["evaluation_queued"] is True
    history = auth_client.get(f"/listings/{body['listing']['id']}/evaluations").json()
    assert len(history) == 1
    assert notified == [history[0]["id"]]


def test_run_evaluation_for_missing_listing_returns_none(test_db):
    assert run_evaluation(123456789, trigger="ingest") is None
