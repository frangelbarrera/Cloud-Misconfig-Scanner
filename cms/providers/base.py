from abc import ABC, abstractmethod
from typing import Iterable
from cms.core.models import ScanResult

class ProviderScanner(ABC):
    @abstractmethod
    def scan(self, targets: Iterable[str] | None = None) -> ScanResult:
        """Run provider-specific scan. `targets` narrows to named buckets/containers."""
        ...
