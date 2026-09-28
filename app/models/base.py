"""Declarative base, naming conventions and column helpers."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Identity, MetaData, Numeric, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {  # noqa: RUF012 - SQLAlchemy class-level mapping
        datetime: DateTime(timezone=True),
        dict[str, Any]: JSONB,
        list[Any]: JSONB,
    }


# Column type shortcuts -------------------------------------------------------------------

Money = Numeric(12, 2)
Score = Numeric(4, 3)  # 0.000 - 1.000
Ratio = Numeric(10, 4)  # e.g. ROI, can exceed 1 or be negative


def pk() -> Mapped[int]:
    return mapped_column(BigInteger, Identity(), primary_key=True)


def created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def updated_at() -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


def money(nullable: bool = False, **kwargs: Any) -> Mapped[Any]:
    return mapped_column(Money, nullable=nullable, **kwargs)


def score(nullable: bool = True, **kwargs: Any) -> Mapped[Any]:
    return mapped_column(Score, nullable=nullable, **kwargs)


# Constraint helpers -----------------------------------------------------------------------


def enum_check(column: str, enum_cls: type[StrEnum], *, nullable: bool = False) -> CheckConstraint:
    allowed = ", ".join(f"'{member.value}'" for member in enum_cls)
    expr = f"{column} IN ({allowed})"
    if nullable:
        expr = f"{column} IS NULL OR {expr}"
    return CheckConstraint(expr, name=f"{column}_valid")


def values_check(column: str, allowed: list[str], *, nullable: bool = False) -> CheckConstraint:
    joined = ", ".join(f"'{value}'" for value in allowed)
    expr = f"{column} IN ({joined})"
    if nullable:
        expr = f"{column} IS NULL OR {expr}"
    return CheckConstraint(expr, name=f"{column}_valid")


def score_check(column: str) -> CheckConstraint:
    return CheckConstraint(
        f"{column} IS NULL OR ({column} >= 0 AND {column} <= 1)", name=f"{column}_range"
    )


def non_negative(column: str) -> CheckConstraint:
    return CheckConstraint(f"{column} IS NULL OR {column} >= 0", name=f"{column}_non_negative")


def currency_check(column: str = "currency") -> CheckConstraint:
    return CheckConstraint(f"{column} IS NULL OR {column} ~ '^[A-Z]{{3}}$'", name=f"{column}_iso")


ZERO = Decimal("0")
