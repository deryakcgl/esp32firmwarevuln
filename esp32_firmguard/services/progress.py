from __future__ import annotations

from typing import Callable, Optional

ProgressCallback = Callable[[int, str], None]


def noop_progress(_percent: int, _message: str) -> None:
    pass


def chain_progress(
    outer: Optional[ProgressCallback],
    base_percent: int,
    span_percent: int,
) -> ProgressCallback:
    """Map inner 0–100 progress into [base, base+span] on outer callback."""

    def _inner(percent: int, message: str) -> None:
        if outer is None:
            return
        p = base_percent + int(span_percent * max(0, min(100, percent)) / 100)
        outer(min(100, p), message)

    return _inner
