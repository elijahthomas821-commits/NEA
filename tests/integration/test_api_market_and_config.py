from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def comp(price, ref, **overrides):
    body = {
        "brand": "Stone Island",
        "category": "sweatshirts",
        "title": "garment dyed crewneck navy",
        "size": "L",
        "condition": "Very good",
        "sale_price": price,
        "sold_at": "2026-09-20T12:00:00Z",
        "source_ref": ref,
    }
    body.update(overrides)
    return body


class TestMarketApi:
    def test_add_list_exclude(self, auth_client):
        created = auth_client.post("/market/sales", json=comp("95.00", "a"))
        assert created.status_code == 201, created.text
        sale = created.json()["sale"]
        assert sale["currency"] == "GBP"
        again = auth_client.post("/market/sales", json=comp("95.00", "a"))
        assert again.status_code == 200
        assert again.json()["created"] is False

        listing = auth_client.get("/market/sales", params={"brand_id": sale["brand_id"]}).json()
        assert listing["total"] == 1
        excluded = auth_client.patch(
            f"/market/sales/{sale['id']}", json={"excluded": True, "reason": "typo"}
        )
        assert excluded.json()["excluded"] is True
        assert auth_client.get("/market/sales").json()["total"] == 0
        assert (
            auth_client.get("/market/sales", params={"include_excluded": True}).json()["total"] == 1
        )

    def test_validation_errors(self, auth_client):
        assert (
            auth_client.post("/market/sales", json=comp("95", "b", brand="Nike")).status_code == 422
        )
        assert auth_client.post("/market/sales", json=comp("-1", "c")).status_code == 422
        assert auth_client.post("/market/sales", json={"brand": "x"}).status_code == 422

    def test_estimate_without_and_with_data(self, auth_client):
        query = {
            "brand": "stone island",
            "category": "sweatshirts",
            "title": "garment dyed crewneck",
            "size": "L",
            "condition": "very good",
        }
        empty = auth_client.post("/market/estimate", json=query).json()
        assert empty["estimate"] is None
        assert "not enough sales data" in empty["message"]
        assert empty["levels_tried"]

        for i, price in enumerate(("90", "95", "100", "105", "110")):
            auth_client.post("/market/sales", json=comp(price, f"e{i}"))
        result = auth_client.post("/market/estimate", json=query).json()
        est = result["estimate"]
        assert est["basis"] == "comps"
        assert est["level"] == "L2"  # no colour in the query, so L1 cannot apply
        assert 95 < float(est["expected"]) < 105
        assert len(result["comps_used"]) == 5

    def test_sales_csv_import(self, auth_client):
        template = auth_client.get("/imports/templates/sales.csv").text
        assert template.startswith("brand,category,product")
        content = (
            "brand,category,sale_price,sold_at\n"
            "moncler,jackets,400,2026-09-01\n"
            "moncler,jackets,abc,2026-09-01\n"
        )
        run = auth_client.post(
            "/imports/sales", files={"file": ("s.csv", content, "text/csv")}
        ).json()
        assert run["status"] == "partial"
        assert run["rows_created"] == 1

    def test_fx_rates(self, auth_client):
        body = {"base": "GBP", "quote": "EUR", "rate": "1.17", "as_of": "2026-09-01"}
        assert auth_client.post("/fx-rates", json=body).status_code == 201
        assert auth_client.get("/fx-rates").json()[0]["quote"] == "EUR"
        assert auth_client.post("/fx-rates", json={**body, "rate": "0"}).status_code == 422

    def test_statistics_endpoint(self, auth_client):
        assert auth_client.get("/market/statistics").json() == []


class TestConfigApi:
    def test_read_and_version(self, auth_client):
        active = auth_client.get("/config").json()
        assert set(active) == {
            "deal_rules", "fees", "conditions", "sizes", "market", "authenticity",
            "identification", "price_guide",
        }  # fmt: skip
        current = auth_client.get("/config/deal_rules").json()
        payload = current["payload"]
        payload["min_profit"] = "30.00"
        updated = auth_client.put("/config/deal_rules", json=payload, params={"note": "raise min"})
        assert updated.status_code == 200, updated.text
        body = updated.json()
        assert body["created"] is True
        assert body["version"] == current["version"] + 1
        assert body["payload"]["min_profit"] == "30.00"

        same = auth_client.put("/config/deal_rules", json=payload).json()
        assert same["created"] is False

        versions = auth_client.get("/config/deal_rules/versions").json()
        assert [v["version"] for v in versions][:2] == [body["version"], current["version"]]
        rolled_back = auth_client.post(
            f"/config/deal_rules/versions/{current['version']}/activate"
        ).json()
        assert rolled_back["is_active"] is True
        assert auth_client.get("/config/deal_rules").json()["version"] == current["version"]

    def test_invalid_config_rejected_with_details(self, auth_client):
        response = auth_client.put("/config/deal_rules", json={"min_profit": "-1", "bogus": 1})
        assert response.status_code == 422
        errors = response.json()["error"]["details"]["errors"]
        assert {e["loc"] for e in errors} >= {"min_profit", "bogus"}

    def test_price_guide_bootstrap(self, auth_client):
        guide = {
            "entries": [
                {
                    "brand": "stone-island",
                    "category": "sweatshirts",
                    "low": "60",
                    "typical": "80",
                    "high": "100",
                }
            ]
        }
        assert auth_client.put("/config/price_guide", json=guide).json()["created"] is True
        est = auth_client.post(
            "/market/estimate", json={"brand": "stone-island", "category": "sweatshirts"}
        ).json()["estimate"]
        assert est["basis"] == "price_guide"
        assert est["level"] == "GUIDE"

    def test_unknown_kind(self, auth_client):
        assert auth_client.get("/config/nope").status_code == 422

    def test_requires_auth(self, client):
        assert client.get("/config").status_code == 401
