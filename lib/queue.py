"""Thin asyncio.Queue wrapper for scan events."""

from __future__ import annotations

import asyncio

from lib.models import FileEvent


class ScanQueue:
    """Bounded async queue for FileEvent objects."""

    def __init__(self, maxsize: int = 0) -> None:
        self._queue: asyncio.Queue[FileEvent] = asyncio.Queue(maxsize=maxsize)

    async def put(self, event: FileEvent) -> None:
        await self._queue.put(event)

    async def get(self) -> FileEvent:
        return await self._queue.get()

    def task_done(self) -> None:
        self._queue.task_done()

    def qsize(self) -> int:
        return self._queue.qsize()
