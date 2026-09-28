"""Purchases, inventory, sales, alerts and analytics through the API."""

from __future__ import annotations

import csv
import io
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.models import Alert, MarketSale
from tests.integration.test_notify import evaluate
from tests.integration.test_pipeline import listing_for, seed_comps

pytestmark = pytest.mark.integration

D = Decimal


def buy(client, *items, **overrides):
    body = {
        "purchase_price": "40.00",
        "buyer_protection_fee": "0",
        "inbound_shipping": "0",
        "purchased_at": "2026-09-01T12:00:00Z",
        "items": list(items) or [{"title": "Stone Island crewneck", "brand": "Stone Island",
                                  "category": "sweatshirts"}],
    }  # fmt: skip
    body.update(overrides)
    response = client.post("/purchases", json=body)
    assert response.status_code == 201, response.json()
    return response.json()


def item_id(purchase, index=0):
    return purchase["items"][index]["id"]


class TestPurchases:
    def test_bundle_with_estimated_fees(self, auth_client):
        purchase = buy(
            auth_client,
            {"title": "Stone Island crewneck", "brand": "Stone Island", "category": "sweatshirts",
             "size": "Large", "expected_resale_price": "110"},
            {"title": "CP Company hoodie", "brand": "cp company", "category": "hoodies",
             "colour": "Grey", "expected_resale_price": "55"},
            purchase_price="80.00", buyer_protection_fee=None, inbound_shipping=None,
        )  # fmt: skip
        assert (purchase["buyer_protection_fee"], purchase["inbound_shipping"]) == ("4.70", "2.99")
        assert purchase["total_acquisition_cost"] == "87.69"
        assert [i["allocated_acquisition_cost"] for i in purchase["items"]] == ["58.46", "29.23"]
        assert purchase["items"][1]["colour"] == "grey"
        assert purchase["items"][0]["size_normalised"] == "L"  # normalised like listings
        assert purchase["items"][0]["status"] == "ordered"
        assert auth_client.get(f"/purchases/{purchase['id']}").json() == purchase
        listed = auth_client.get("/purchases").json()
        assert listed["total"] == 1
        assert auth_client.get("/purchases/999999").status_code == 404

    def test_from_listings_uses_their_evaluations(
        self, auth_client, db_session, tmp_path, recorder
    ):
        seed_comps(recorder)
        listing = listing_for(db_session)
        evaluation = evaluate(db_session, tmp_path, listing)
        purchase = buy(
            auth_client, {"listing_id": listing.id}, purchase_price="45.00",
            buyer_protection_fee=None, inbound_shipping=None,
        )  # fmt: skip
        assert purchase["total_acquisition_cost"] == "50.94"
        (item,) = purchase["items"]
        assert D(item["expected_resale_price"]) == evaluation.expected_sale_price
        detail = auth_client.get(f"/inventory/{item['id']}").json()
        assert detail["prediction"]["evaluation_id"] == evaluation.id
        again = auth_client.post(
            "/purchases", json={"purchase_price": "1", "items": [{"listing_id": listing.id}]}
        )
        assert again.status_code == 409

    @pytest.mark.parametrize(
        ("overrides", "status", "message"),
        [
            ({"items": [{"title": "x", "brand": "Nobody"}]}, 422, "unknown brand"),
            ({"items": [{"title": "x", "category": "shoes"}]}, 422, "unknown category"),
            ({"items": [{"listing_id": 999999}]}, 404, "listing 999999"),
            ({"items": [{"brand": "Stone Island"}]}, 422, "listing_id or a title"),
            ({"items": []}, 422, "validation"),
            ({"marketplace": "nowhere"}, 422, "unknown marketplace"),
            (
                {"allocation": "manual",
                 "items": [{"title": "a", "allocated_cost": "10"},
                           {"title": "b", "allocated_cost": "10"}]},
                422,
                "add up to",
            ),
            ({"purchase_price": "-1"}, 422, "validation"),
        ],
    )  # fmt: skip
    def test_invalid(self, auth_client, overrides, status, message):
        body = {"purchase_price": "40.00", "items": [{"title": "x"}]}
        body.update(overrides)
        response = auth_client.post("/purchases", json=body)
        assert response.status_code == status
        assert message in str(response.json())

    def test_requires_auth(self, client):
        assert client.post("/purchases", json={}).status_code == 401
        assert client.get("/inventory").status_code == 401
        assert client.get("/analytics/summary").status_code == 401


class TestInventoryFlow:
    def test_lifecycle_and_sale(self, auth_client, db_session):
        item = item_id(buy(auth_client))
        received = auth_client.post(
            f"/inventory/{item}/status",
            json={"status": "received", "at": "2026-09-03T10:00:00Z", "condition": "Very good"},
        ).json()
        assert received["item"]["condition_on_receipt"] == "very_good"
        auth_client.patch(f"/inventory/{item}", json={"cleaning_cost": "4.50", "notes": "washed"})
        auth_client.post(
            f"/inventory/{item}/status",
            json={"status": "listed", "at": "2026-09-04T10:00:00Z", "listed_price": "99.00"},
        )
        wrong = auth_client.post(f"/inventory/{item}/status", json={"status": "sold"})
        assert wrong.status_code == 409
        assert "record the sale" in wrong.json()["error"]["message"]

        sold = auth_client.post(
            f"/inventory/{item}/sale",
            json={"sale_price": "95.00", "sold_at": "2026-09-14T10:00:00Z"},
        )
        assert sold.status_code == 201
        detail = sold.json()
        assert detail["sale"]["net_proceeds"] == "94.50"  # £0.50 packaging from your fees
        assert detail["profit"] == "50.00"  # 94.50 − (40.00 + 4.50)
        assert detail["days_held"] == 13
        assert [e["to_status"] for e in detail["events"]] == [
            "ordered",
            "received",
            "listed",
            "sold",
        ]
        assert db_session.get(MarketSale, detail["sale"]["market_sale_id"]).source == "own_sale"
        assert (
            auth_client.post(f"/inventory/{item}/sale", json={"sale_price": "95.00"}).status_code
            == 409
        )

        resale_id = detail["sale"]["id"]
        patched = auth_client.patch(f"/resales/{resale_id}", json={"refunds": "5.00"}).json()
        assert patched["net_proceeds"] == "89.50"
        assert auth_client.get(f"/resales/{resale_id}").json() == patched

        auth_client.post(f"/inventory/{item}/status", json={"status": "shipped"})
        back = auth_client.post(f"/resales/{resale_id}/cancel", json={"reason": "no show"}).json()
        assert back["item"]["status"] == "listed"
        assert back["sale"] is None
        assert auth_client.get(f"/resales/{resale_id}").status_code == 404

        filtered = auth_client.get("/inventory", params={"status": ["listed", "received"]}).json()
        assert [i["id"] for i in filtered["items"]] == [item]
        assert auth_client.get("/inventory", params={"status": "sold"}).json()["total"] == 0

    def test_missing_things(self, auth_client):
        assert auth_client.get("/inventory/999999").status_code == 404
        assert (
            auth_client.post("/inventory/999999/status", json={"status": "received"}).status_code
            == 404
        )
        assert auth_client.patch("/resales/999999", json={"refunds": "1"}).status_code == 404
        assert auth_client.post("/resales/999999/cancel", json={}).status_code == 404


class TestAlerts:
    def test_list_and_decide(self, auth_client, db_session, tmp_path, recorder):
        seed_comps(recorder)
        listing = listing_for(db_session)
        evaluation = evaluate(db_session, tmp_path, listing)
        db_session.add(
            Alert(evaluation_id=evaluation.id, listing_id=listing.id, priority="review",
                  status="sent")
        )  # fmt: skip
        db_session.commit()
        alerts = auth_client.get("/alerts", params={"undecided": True}).json()
        assert alerts["total"] == 1
        alert_id = alerts["items"][0]["id"]
        decided = auth_client.post(
            f"/alerts/{alert_id}/decision", json={"decision": "pass", "note": "too worn"}
        ).json()
        assert (decided["user_decision"], decided["decision_note"]) == ("pass", "too worn")
        assert auth_client.get("/alerts", params={"undecided": True}).json()["total"] == 0
        assert auth_client.get("/alerts", params={"decision": "pass"}).json()["total"] == 1
        assert auth_client.get("/alerts", params={"priority": "high"}).json()["total"] == 0
        assert auth_client.get("/alerts", params={"status": "sent"}).json()["total"] == 1
        assert (
            auth_client.post("/alerts/999999/decision", json={"decision": "buy"}).status_code == 404
        )
        stored = db_session.scalar(select(Alert).where(Alert.id == alert_id))
        assert stored is not None


class TestAnalytics:
    @pytest.fixture
    def september(self, auth_client):
        """X sold for £60 profit, Y for £15 (after £5 cleaning), Z written off, W in stock."""

        def listed(item, day):
            auth_client.post(
                f"/inventory/{item}/status",
                json={"status": "received", "at": f"2026-09-{day:02d}T09:00:00Z"},
            )
            auth_client.post(
                f"/inventory/{item}/status",
                json={"status": "listed", "at": f"2026-09-{day:02d}T10:00:00Z"},
            )

        x = item_id(
            buy(
                auth_client,
                {
                    "title": '=HYPERLINK("http://x")',
                    "brand": "Stone Island",
                    "category": "sweatshirts",
                },
                purchase_price="40.00",
            )
        )
        y = item_id(
            buy(
                auth_client,
                {"title": "CP hoodie", "brand": "CP Company", "category": "hoodies"},
                purchase_price="30.00",
                purchased_at="2026-09-02T12:00:00Z",
            )
        )
        z = item_id(
            buy(
                auth_client,
                {"title": "Moncler"},
                purchase_price="20.00",
                purchased_at="2026-09-03T12:00:00Z",
            )
        )
        w = item_id(
            buy(
                auth_client,
                {"title": "Burberry"},
                purchase_price="25.00",
                purchased_at="2026-09-05T12:00:00Z",
            )
        )
        auth_client.patch(f"/inventory/{y}", json={"cleaning_cost": "5.00"})
        listed(x, 4)
        listed(y, 6)
        for item, price, day in ((x, "100.00", 10), (y, "50.00", 20)):
            auth_client.post(
                f"/inventory/{item}/sale",
                json={
                    "sale_price": price,
                    "sold_at": f"2026-09-{day}T12:00:00Z",
                    "other_selling_costs": "0",
                },
            )
        auth_client.post(
            f"/inventory/{z}/status", json={"status": "written_off", "at": "2026-09-25T12:00:00Z"}
        )
        return {"x": x, "y": y, "z": z, "w": w}  # fmt: skip

    def test_summary_reconciles(self, auth_client, september):
        report = auth_client.get(
            "/analytics/summary", params={"from": "2026-09-01", "to": "2026-09-30"}
        ).json()
        s = report["summary"]
        assert (s["items_bought"], s["spend"]) == (4, "115.00")
        sales = s["sales"]
        assert (sales["items_sold"], sales["revenue"], sales["cost_of_sold"]) == (
            2,
            "150.00",
            "75.00",
        )
        assert (sales["realised_profit"], sales["roi"], sales["margin"]) == (
            "75.00",
            "1.0000",
            "0.5000",
        )
        assert (sales["win_rate"], sales["average_days_to_sell"]) == ("1.0000", "13.5")
        assert (s["written_off"], s["write_off_loss"], s["net_result"]) == (1, "20.00", "55.00")
        assert s["sell_through"] == "0.6667"  # 2 ÷ (2 + W)
        stock = report["stock"]
        assert (stock["items"], stock["capital"], stock["by_status"]) == (
            1,
            "25.00",
            {"ordered": 1},
        )
        assert report["currency"] == "GBP"

    def test_breakdown_predictions_funnel(self, auth_client, september):
        rows = auth_client.get("/analytics/breakdown", params={"by": "brand"}).json()
        assert [(r["key"], r["sales"]["realised_profit"]) for r in rows] == [
            ("Stone Island", "60.00"),
            ("C.P. Company", "15.00"),
        ]
        assert auth_client.get("/analytics/breakdown", params={"by": "nope"}).status_code == 422
        accuracy = auth_client.get("/analytics/predictions").json()
        assert accuracy["overall"]["resolved"] == 0  # bought by hand: nothing was predicted
        funnel = auth_client.get("/analytics/funnel", params={"from": "2026-09-01"}).json()
        assert (funnel["purchases"], funnel["items_bought"], funnel["buy_rate"]) == (4, 4, None)
        bad = auth_client.get(
            "/analytics/summary", params={"from": "2026-09-30", "to": "2026-09-01"}
        )
        assert bad.status_code == 422

    def test_csv_exports(self, auth_client, september):
        response = auth_client.get("/analytics/export/inventory.csv")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert 'filename="inventory.csv"' in response.headers["content-disposition"]
        rows = list(csv.DictReader(io.StringIO(response.text)))
        assert len(rows) == 4
        by_id = {int(r["item_id"]): r for r in rows}
        assert by_id[september["x"]]["title"] == '\'=HYPERLINK("http://x")'  # not a formula
        assert by_id[september["x"]]["profit"] == "60.00"
        assert by_id[september["z"]]["status"] == "written_off"

        sales = list(
            csv.DictReader(io.StringIO(auth_client.get("/analytics/export/sales.csv").text))
        )
        assert [r["net_proceeds"] for r in sales] == ["100.00", "50.00"]
        evaluations = auth_client.get("/analytics/export/evaluations.csv")
        assert evaluations.text.startswith("evaluation_id,")
        assert auth_client.get("/analytics/export/secrets.csv").status_code == 422
        september_only = auth_client.get(
            "/analytics/export/sales.csv", params={"from": "2026-09-15"}
        ).text
        assert len(list(csv.DictReader(io.StringIO(september_only)))) == 1
