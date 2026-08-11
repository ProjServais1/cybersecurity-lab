from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator


class Collector(ABC):
    """Contract implemented by all SentinelLab event collectors."""

    @abstractmethod
    def collect(self) -> Iterator[str]:
        """
        Collect raw security data.

        Yields:
            Raw events as strings.
        """
        raise NotImplementedError
