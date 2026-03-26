"""Protocol definition for file-system watchers."""

from __future__ import annotations

from typing import Protocol

from lib.queue import ScanQueue


class WatcherBase(Protocol):
    async def start(self, queue: ScanQueue) -> None:
        """Start watching and push FileEvent objects onto the queue."""
        ...

    async def stop(self) -> None:
        """Stop watching and clean up."""
        ...

    @property
    def watch_count(self) -> int:
        """Number of active directory watches."""
        ...
