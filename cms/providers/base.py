"""Base classes for provider scanners.

All provider scanners should subclass :class:`ProviderScanner` and implement
:meth:`scan`. The base class provides shared helpers (resource factory,
simulated-mode detection) so that provider implementations stay small and
consistent.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from cms.core.models import Resource, ScanResult


class ProviderScanner(ABC):
    """Abstract base class for all cloud-provider scanners.

    Subclasses are expected to set ``self.provider`` and ``self.service``
    in their constructor and call ``self._resource(name, meta)`` to build
    :class:`Resource` instances.
    """

    provider: str = "unknown"
    service: str = "unknown"

    @abstractmethod
    def scan(self, targets: Iterable[str] | None = None) -> ScanResult:
        """Run provider-specific scan.

        ``targets`` narrows the scan to named buckets/containers when
        provided. Implementations should still run account-level checks
        regardless of ``targets``.
        """
        raise NotImplementedError

    def _resource(
        self,
        name: str,
        account: str = "000000000000",
        region: str | None = None,
        meta: dict | None = None,
    ) -> Resource:
        """Build a :class:`Resource` tagged with this scanner's provider."""
        return Resource(
            provider=self.provider,
            service=self.service,
            account=account,
            region=region,
            name=name,
            meta=meta or {},
        )
