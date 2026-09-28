from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_list_brands_and_categories(auth_client):
    brands = auth_client.get("/brands").json()
    assert {b["slug"] for b in brands} == {
        "stone-island", "cp-company", "ralph-lauren", "moncler", "burberry",
    }  # fmt: skip
    si = next(b for b in brands if b["slug"] == "stone-island")
    assert "stone island" in si["aliases"]
    assert "stone island style" in si["negative_aliases"]
    categories = auth_client.get("/categories").json()
    assert {c["slug"] for c in categories if c["in_scope"]} == {"sweatshirts", "hoodies", "jackets"}


def test_create_brand_adds_generic_products(auth_client):
    response = auth_client.post(
        "/brands",
        json={
            "name": "Barbour",
            "aliases": ["barbour international"],
            "base_authenticity_risk": "0.2",
        },
    )
    assert response.status_code == 201, response.text
    brand = response.json()
    assert brand["slug"] == "barbour"
    products = auth_client.get("/products", params={"brand_id": brand["id"]}).json()
    assert len(products) == 3
    assert all(p["level"] == "brand_category_generic" for p in products)
    assert auth_client.post("/brands", json={"name": "Barbour"}).status_code == 409


def test_aliases(auth_client):
    brand = next(b for b in auth_client.get("/brands").json() if b["slug"] == "moncler")
    added = auth_client.post(f"/brands/{brand['id']}/aliases", json={"alias": "Monclair"})
    assert added.status_code == 201
    assert "monclair" in added.json()["aliases"]
    dup = auth_client.post(f"/brands/{brand['id']}/aliases", json={"alias": "MONCLAIR"})
    assert dup.status_code == 409
    assert auth_client.post("/brands/999999/aliases", json={"alias": "x"}).status_code == 404


def test_products(auth_client):
    brands = {b["slug"]: b for b in auth_client.get("/brands").json()}
    categories = {c["slug"]: c for c in auth_client.get("/categories").json()}
    body = {
        "brand_id": brands["stone-island"]["id"],
        "category_id": categories["jackets"]["id"],
        "name": "Stone Island Raso Gommato jacket",
        "level": "model",
        "aliases": ["raso gommato", "Raso-Gommato"],
    }
    created = auth_client.post("/products", json=body)
    assert created.status_code == 201, created.text
    product = created.json()
    assert product["aliases"] == ["raso gommato"]
    alias = auth_client.post(
        f"/products/{product['id']}/aliases", json={"alias": "gommato", "weight": "0.8"}
    )
    assert alias.status_code == 201
    assert auth_client.post("/products", json=body).status_code == 409
    generic = {**body, "name": "x", "level": "brand_category_generic"}
    assert auth_client.post("/products", json=generic).status_code == 422

    preview = auth_client.post(
        "/identify", json={"title": "Stone Island raso gommato jacket L"}
    ).json()
    assert preview["match"]["product_id"] == product["id"]


def test_identify_preview(auth_client):
    body = auth_client.post(
        "/identify",
        json={"title": "CP Company goggle hoodie navy M", "condition": "Very good"},
    ).json()
    ident = body["identification"]
    assert ident["brand_slug"] == "cp-company"
    assert ident["category_slug"] == "hoodies"
    assert ident["size"]["normalised"] == "M"
    assert ident["condition"] == "very_good"
    assert body["match"]["method"] == "alias"


def test_category_keyword(auth_client):
    jackets = next(c for c in auth_client.get("/categories").json() if c["slug"] == "jackets")
    assert (
        auth_client.post(
            f"/categories/{jackets['id']}/keywords", json={"keyword": "shacket"}
        ).status_code
        == 201
    )
    assert (
        auth_client.post(
            f"/categories/{jackets['id']}/keywords", json={"keyword": "hoodie"}
        ).status_code
        == 409
    )
