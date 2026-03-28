"""SHA-256 hash cache — skip re-scanning unchanged files."""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)


class HashCache:
    """LRU-ish cache of file SHA-256 hashes to skip re-scanning clean files."""

    def __init__(self, persist_path: Path | None = None, max_entries: int = 10000) -> None:
        self._cache: dict[str, str] = {}  # path -> sha256
        self._clean: set[str] = set()     # sha256 hashes known to be clean
        self._max_entries = max_entries
        self._persist_path = persist_path
        self._lock = threading.Lock()
        if persist_path:
            self._load()

    def get_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content).hexdigest()

    def is_known_clean(self, file_hash: str) -> bool:
        """Check if a hash is in the known-clean set."""
        with self._lock:
            return file_hash in self._clean

    def mark_clean(self, file_hash: str) -> None:
        """Mark a hash as known-clean."""
        with self._lock:
            self._clean.add(file_hash)
            self._evict_if_needed()

    def mark_dirty(self, file_hash: str) -> None:
        """Remove a hash from the known-clean set (file had findings)."""
        with self._lock:
            self._clean.discard(file_hash)

    def _evict_if_needed(self) -> None:
        """Evict oldest entries if cache exceeds max size."""
        if len(self._clean) > self._max_entries:
            excess = len(self._clean) - self._max_entries
            to_remove = excess + (self._max_entries // 10)
            # Collect items to remove first, then discard (cannot modify set during iteration)
            remove_items = list(itertools.islice(self._clean, to_remove))
            self._clean -= set(remove_items)

    def save(self) -> None:
        """Persist cache to disk."""
        if not self._persist_path:
            return
        with self._lock:
            try:
                self._persist_path.parent.mkdir(parents=True, exist_ok=True)
                data = {"clean": list(self._clean)[:self._max_entries]}
                self._persist_path.write_text(json.dumps(data), encoding="utf-8")
            except OSError:
                logger.warning("Failed to save hash cache to %s", self._persist_path)

    def _load(self) -> None:
        """Load cache from disk."""
        if not self._persist_path or not self._persist_path.is_file():
            return
        try:
            data = json.loads(self._persist_path.read_text(encoding="utf-8"))
            clean_list = data.get("clean", [])
            if isinstance(clean_list, list):
                self._clean = set(clean_list[:self._max_entries])
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to load hash cache from %s", self._persist_path)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._clean)
