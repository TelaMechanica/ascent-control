"""Host-only Service Mode boundary; never export this object to widget code.

A backend is supplied by the trusted application, not by packages or HTTP input.
No enrollment, credential storage, network transport or executor is implemented.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Protocol


class AccessDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class ReceiverBinding:
    selection_epoch: int
    receiver_identity: str
    transport_identity: str


@dataclass(frozen=True)
class ServiceState:
    provider_loaded: bool
    enabled: bool
    binding: ReceiverBinding | None


class ReceiverBackend(Protocol):
    def acquire(self, binding: ReceiverBinding): ...
    def close(self, session): ...


@dataclass(frozen=True)
class ServiceLease:
    """Trusted-host session plus cooperative liveness check; never a widget API."""
    session: object
    check: Callable[[], None]


class ServiceAccess:
    """Recheck application-owned state before and after session acquisition.

    The caller holds the selected-device operation lock throughout the lease.
    The backend must preserve enrollment, pinned host key and identity checks.
    Call lease.check() between bounded backend steps. Blocking calls cannot be
    preempted by this cooperative hook. Python object privacy is not a sandbox
    or a cryptographic trust root.
    """
    def __init__(self, *, state, backend: ReceiverBackend, operation_lock):
        self._state = state
        self._backend = backend
        self._lock = operation_lock

    def _require(self, binding):
        current = self._state()
        if not current.provider_loaded or not current.enabled:
            raise AccessDenied('SERVICE_MODE_UNAVAILABLE')
        if not isinstance(binding, ReceiverBinding) or not binding.receiver_identity or not binding.transport_identity:
            raise AccessDenied('RECEIVER_BINDING_REQUIRED')
        if current.binding != binding:
            raise AccessDenied('RECEIVER_BINDING_CHANGED')

    @contextmanager
    def lease(self, binding):
        with self._lock:
            self._require(binding)
            session = self._backend.acquire(binding)
            active = True
            def check():
                if not active:
                    raise AccessDenied('SERVICE_LEASE_CLOSED')
                self._require(binding)
            try:
                check()
                yield ServiceLease(session, check)
            finally:
                active = False
                self._backend.close(session)
