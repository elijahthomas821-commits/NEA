from __future__ import annotations

from decimal import Decimal

import pytest
from sqlalchemy import select

from tests.factories import image_bytes

pytestmark = pytest.mark.integration

LINK = "https://www.vinted.co.uk/items/4829301234-stone-island-crewneck-sweatshirt"


class TestSubmit:
    def test_requires_auth(self, client):
        assert client.post("/listings", json={"title": "x"}).status_code == 401

    def test_submit_json(self, auth_client, dispatcher):
        response = auth_client.post(
            "/listings",
            json={"url": LINK, "price": "45.00", "size": "L / 40 / 12", "condition": "Very good"},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["created"] is True
        assert body["evaluation_queued"] is True
        listing = body["listing"]
        assert listing["external_id"] == "4829301234"
        assert listing["title"] == "stone island crewneck sweatshirt"
        assert listing["currency"] == "GBP"
        assert listing["raw_size"] == "L"
        assert dispatcher.calls == [
            (
                "evaluate_listing",
                {"listing_id": listing["id"], "trigger": "ingest", "alert": "always"},
            )
        ]

    def test_resubmit_unchanged_is_200_and_not_requeued(self, auth_client, dispatcher):
        payload = {"url": LINK, "price": "45.00"}
        auth_client.post("/listings", json=payload)
        response = auth_client.post("/listings", json=payload)
        assert response.status_code == 200
        assert response.json()["evaluation_queued"] is False
        assert len(dispatcher.calls) == 1

    def test_missing_price_reported(self, auth_client):
        body = auth_client.post("/listings", json={"title": "CP Company goggle hoodie"}).json()
        assert body["missing_fields"] == ["price"]
        assert body["listing"]["external_id"].startswith("manual-")

    def test_title_required_without_link(self, auth_client):
        response = auth_client.post("/listings", json={"price": "10"})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_failed"

    def test_rejects_unknown_fields_and_bad_values(self, auth_client):
        assert auth_client.post("/listings", json={"title": "x", "bogus": 1}).status_code == 422
        assert auth_client.post("/listings", json={"title": "x", "price": "-3"}).status_code == 422
        assert (
            auth_client.post(
                "/listings", json={"title": "x", "url": "javascript:alert(1)"}
            ).status_code
            == 422
        )

    def test_quick_submit(self, auth_client):
        response = auth_client.post("/listings/quick", json={"text": f"{LINK} £45 L very good"})
        assert response.status_code == 201
        listing = response.json()["listing"]
        assert listing["price"] == "45.00"


class TestReadAndUpdate:
    def test_list_get_patch(self, auth_client, dispatcher):
        created = auth_client.post("/listings", json={"url": LINK, "price": "45"}).json()
        listing_id = created["listing"]["id"]

        page = auth_client.get("/listings", params={"q": "crewneck"}).json()
        assert page["total"] >= 1
        assert any(item["id"] == listing_id for item in page["items"])

        assert auth_client.get(f"/listings/{listing_id}").json()["id"] == listing_id
        assert auth_client.get("/listings/999999999").status_code == 404

        patched = auth_client.patch(f"/listings/{listing_id}", json={"price": "39.00"})
        assert patched.status_code == 200
        assert patched.json()["evaluation_queued"] is True
        assert dispatcher.calls[-1][1]["trigger"] == "price_change"

        history = auth_client.get(f"/listings/{listing_id}/price-history").json()
        assert [h["price"] for h in history] == ["45.00", "39.00"]

        sold = auth_client.patch(f"/listings/{listing_id}", json={"status": "sold"}).json()
        assert sold["listing"]["status"] == "sold"
        assert sold["evaluation_queued"] is False

    def test_search_escapes_wildcards(self, auth_client):
        auth_client.post("/listings", json={"title": "Plain title", "price": "5"})
        page = auth_client.get("/listings", params={"q": "%"}).json()
        assert all("%" in item["title"] for item in page["items"])

    def test_pagination_bounds(self, auth_client):
        assert auth_client.get("/listings", params={"limit": 0}).status_code == 422
        assert auth_client.get("/listings", params={"limit": 101}).status_code == 422


class TestImagesApi:
    def test_upload_images(self, auth_client, dispatcher):
        listing_id = auth_client.post("/listings", json={"title": "x", "price": "5"}).json()[
            "listing"
        ]["id"]
        dispatcher.calls.clear()
        files = [
            ("files", ("a.jpg", image_bytes(seed=1), "image/jpeg")),
            ("files", ("b.png", image_bytes(seed=2, fmt="PNG"), "image/png")),
        ]
        response = auth_client.post(f"/listings/{listing_id}/images", files=files)
        assert response.status_code == 200, response.text
        assert [img["position"] for img in response.json()] == [0, 1]
        assert dispatcher.calls
        assert dispatcher.calls[0][1]["trigger"] == "manual"
        listed = auth_client.get(f"/listings/{listing_id}/images").json()
        assert len(listed) == 2

    def test_invalid_image(self, auth_client):
        listing_id = auth_client.post("/listings", json={"title": "x", "price": "5"}).json()[
            "listing"
        ]["id"]
        response = auth_client.post(
            f"/listings/{listing_id}/images", files=[("files", ("a.jpg", b"nope", "image/jpeg"))]
        )
        assert response.status_code == 422

    def test_oversized_request_rejected_early(self, auth_client, app):
        app.state.settings = app.state.settings.model_copy(update={"max_request_bytes": 1024})
        response = auth_client.post(
            "/listings/1/images", files=[("files", ("a.jpg", b"x" * 5000, "image/jpeg"))]
        )
        assert response.status_code == 413


class TestImportsApi:
    def test_import_and_fetch_report(self, auth_client):
        template = auth_client.get("/imports/templates/listings.csv")
        assert template.status_code == 200
        assert template.text.startswith("marketplace,external_id")
        content = b"title,price,currency\nStone Island hoodie,45,GBP\n,1,GBP\n"
        response = auth_client.post(
            "/imports/listings", files={"file": ("x.csv", content, "text/csv")}
        )
        assert response.status_code == 201
        run = response.json()
        assert run["status"] == "partial"
        assert auth_client.get(f"/imports/{run['id']}").json()["rows_failed"] == 1
        assert auth_client.get("/imports/99999").status_code == 404


def test_marking_sold_keeps_the_last_asking_price(auth_client, db_session):
    """A listing that sold to someone else becomes a (weak) market observation."""
    from app.core.enums import PriceType, SaleSource
    from app.models import Brand, Category, Listing, MarketSale

    listing_id = auth_client.post("/listings", json={"url": LINK, "price": "95"}).json()["listing"][
        "id"
    ]
    listing = db_session.get(Listing, listing_id)
    listing.brand_id = db_session.scalar(select(Brand.id).where(Brand.slug == "stone-island"))
    listing.category_id = db_session.scalar(
        select(Category.id).where(Category.slug == "sweatshirts")
    )
    db_session.commit()
    auth_client.patch(f"/listings/{listing_id}", json={"status": "sold"})
    sale = db_session.scalar(select(MarketSale).where(MarketSale.listing_id == listing_id))
    assert sale.source == SaleSource.OBSERVED_SOLD_LISTING.value
    assert sale.price_type == PriceType.LAST_ASKING_PRICE.value
    assert sale.sale_price == Decimal("95.00")
    assert sale.created_by_user_id is not None
