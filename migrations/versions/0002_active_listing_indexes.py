"""Partial indexes on active listings (sale-speed counts by product, brand/category, category).

Revision ID: 0002_active_listing_idx
Revises: 0001_initial
Create Date: 2026-09-28 11:35:31.963097

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_active_listing_idx"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_listings_active_brand_category",
        "listings",
        ["brand_id", "category_id"],
        unique=False,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_listings_active_category",
        "listings",
        ["category_id"],
        unique=False,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_listings_active_product",
        "listings",
        ["matched_product_id"],
        unique=False,
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_listings_active_product",
        table_name="listings",
        postgresql_where=sa.text("status = 'active'"),
    )
    op.drop_index(
        "ix_listings_active_category",
        table_name="listings",
        postgresql_where=sa.text("status = 'active'"),
    )
    op.drop_index(
        "ix_listings_active_brand_category",
        table_name="listings",
        postgresql_where=sa.text("status = 'active'"),
    )
