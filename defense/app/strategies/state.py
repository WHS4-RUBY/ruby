"""Bounded, expiring state for multi-request defense strategies."""

import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import os
import time


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass
class StateEntry:
    state: dict = field(default_factory=dict)
    touched_at: float = 0
    users: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class StateCapacityError(Exception):
    pass


class StrategyStateStore:
    def __init__(self, *, max_entries: int | None = None, ttl_seconds: int | None = None, clock=None):
        self.max_entries = max_entries or _positive_int("DEFENSE_STATE_LIMIT", 10000)
        self.ttl_seconds = ttl_seconds or _positive_int("DEFENSE_STATE_TTL_SECONDS", 600)
        self._clock = clock or time.monotonic
        self._entries: OrderedDict[tuple[str, str], StateEntry] = OrderedDict()
        self._lock = asyncio.Lock()

    def _prune(self, now: float) -> None:
        for key, entry in list(self._entries.items()):
            if not entry.users and now - entry.touched_at >= self.ttl_seconds:
                del self._entries[key]

    @asynccontextmanager
    async def use(self, strategy: str, client_id: str):
        key = (strategy, client_id)
        async with self._lock:
            now = self._clock()
            self._prune(now)
            entry = self._entries.get(key)
            if entry is None:
                if len(self._entries) >= self.max_entries:
                    for old_key, old_entry in self._entries.items():
                        if not old_entry.users:
                            del self._entries[old_key]
                            break
                    else:
                        raise StateCapacityError("defense strategy state is full")
                entry = StateEntry(touched_at=now)
                self._entries[key] = entry
            entry.users += 1
            self._entries.move_to_end(key)

        try:
            async with entry.lock:
                yield entry
        finally:
            async with self._lock:
                entry.users -= 1
                entry.touched_at = self._clock()

    async def size(self) -> int:
        async with self._lock:
            self._prune(self._clock())
            return len(self._entries)
