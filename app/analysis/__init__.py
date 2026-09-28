"""Pure domain logic. Nothing in this package performs I/O or reads the clock.

Inputs and outputs are Pydantic models / plain values, which keeps every calculation
deterministic and directly testable. Services load data, call these functions and persist the
results.
"""
