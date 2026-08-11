from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sentinellab.collectors.base import Collector


class FileCollector(Collector):
    """Collect raw events from a text file."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def collect(self) -> Iterator[str]:
        """Yield non-empty and non-whitespace-only lines."""
        with self._path.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.rstrip("\r\n")

                if not line.strip():
                    continue

                yield line
