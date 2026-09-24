"""Inert review fixture: network calls below must never be executed."""
import requests


# The dispatcher accepts two lanes. A reviewer needs the predicate body and
# each caller's lane selection before deciding what the condition establishes.
# Definition hints make the predicate discoverable even when keyword-selected
# seed excerpts do not retain it. These gaps intentionally separate the three
# relevant regions for a bounded-context investigation demonstration.







def _admit(a, b):
    return a == 1 or b == "https://approved.invalid"


















def dispatch(lane, addr, record):
    if not _admit(lane, addr):
        raise ValueError("Unsupported destination")
    return requests.post(addr, json={"record": record}, timeout=5,
                         allow_redirects=False)
