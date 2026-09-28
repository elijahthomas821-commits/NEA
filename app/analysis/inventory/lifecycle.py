"""Which status changes an inventory item may make.

    ordered → in_transit → received → needs_work ⇄ ready_to_list ⇄ listed → sold → shipped
                                                                          → completed

* ``sold`` is only reached by recording the sale (so every sold item has its sale figures);
  cancelling a sale that fell through returns the item to ``listed``.
* ``returned`` means you sent the item back to its seller for a refund (e.g. not as described).
* ``written_off`` means it is lost, unsellable or kept: its whole cost is a loss.
* ``completed``, ``returned`` and ``written_off`` are final.
"""

from __future__ import annotations

from app.core.enums import InventoryStatus as S

TRANSITIONS: dict[S, frozenset[S]] = {
    S.ORDERED: frozenset({S.IN_TRANSIT, S.RECEIVED, S.RETURNED, S.WRITTEN_OFF}),
    S.IN_TRANSIT: frozenset({S.RECEIVED, S.RETURNED, S.WRITTEN_OFF}),
    S.RECEIVED: frozenset(
        {S.NEEDS_WORK, S.READY_TO_LIST, S.LISTED, S.SOLD, S.RETURNED, S.WRITTEN_OFF}
    ),
    S.NEEDS_WORK: frozenset({S.READY_TO_LIST, S.LISTED, S.SOLD, S.WRITTEN_OFF}),
    S.READY_TO_LIST: frozenset({S.NEEDS_WORK, S.LISTED, S.SOLD, S.WRITTEN_OFF}),
    S.LISTED: frozenset({S.READY_TO_LIST, S.NEEDS_WORK, S.SOLD, S.WRITTEN_OFF}),
    S.SOLD: frozenset({S.SHIPPED, S.COMPLETED}),
    S.SHIPPED: frozenset({S.COMPLETED}),
    S.COMPLETED: frozenset(),
    S.RETURNED: frozenset(),
    S.WRITTEN_OFF: frozenset(),
}

# Money is tied up in these (the deal engine's exposure limit counts them).
IN_STOCK: frozenset[S] = frozenset(
    {S.ORDERED, S.IN_TRANSIT, S.RECEIVED, S.NEEDS_WORK, S.READY_TO_LIST, S.LISTED}
)
# A sale can be recorded from these.
SELLABLE: frozenset[S] = frozenset({S.RECEIVED, S.NEEDS_WORK, S.READY_TO_LIST, S.LISTED})
# Sold, with a sale record.
SOLD_STATES: frozenset[S] = frozenset({S.SOLD, S.SHIPPED, S.COMPLETED})
FINAL: frozenset[S] = frozenset({S.COMPLETED, S.RETURNED, S.WRITTEN_OFF})
# Leaving stock for good (the date an item stops tying up money).
EXITS: frozenset[S] = frozenset({S.SOLD, S.RETURNED, S.WRITTEN_OFF})


class TransitionError(ValueError):
    pass


def check_transition(current: S, target: S) -> None:
    """Raise :class:`TransitionError` unless ``current → target`` is allowed by hand.

    ``sold`` is never set by hand: record the sale instead.
    """
    if target is S.SOLD:
        raise TransitionError("record the sale (price and costs) to mark an item sold")
    if current is target:
        raise TransitionError(f"the item is already {current.value}")
    if target not in TRANSITIONS[current]:
        allowed = sorted(s.value for s in TRANSITIONS[current] if s is not S.SOLD)
        hint = f"; from {current.value} it can go to: {', '.join(allowed)}" if allowed else ""
        raise TransitionError(f"an item that is {current.value} can't become {target.value}{hint}")


def can_sell(current: S) -> bool:
    return current in SELLABLE
