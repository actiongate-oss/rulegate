# Copyright 2026 actiongate-oss
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Event emitter for gate decision listeners."""

from __future__ import annotations

from typing import Any, Callable


class Emitter:
    """Decoupled listener bus for gate decisions.

    Listeners are fire-and-forget: exceptions are counted
    but never block gate evaluation or action execution.

    Can be shared across engines to create a unified event bus.
    """

    __slots__ = ("_listeners", "_errors")

    def __init__(self) -> None:
        self._listeners: list[Callable[[Any], None]] = []
        self._errors = 0

    def add(self, listener: Callable[[Any], None]) -> None:
        """Register a listener."""
        self._listeners.append(listener)

    def emit(self, event: Any) -> None:
        """Notify all listeners. Exceptions are swallowed and counted."""
        for listener in self._listeners:
            try:
                listener(event)
            except Exception:
                self._errors += 1

    @property
    def error_count(self) -> int:
        """Number of listener exceptions (never blocks execution)."""
        return self._errors
