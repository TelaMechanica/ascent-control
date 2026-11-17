"""Single-worker trusted-host catalog observations; no activation or installation."""
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import RLock, Thread
from time import monotonic

from .widget_catalog import scan_folder

MAX_RESULT_BYTES = 256 * 1024
SCAN_DELAY_SECONDS = 5.0
_FIELDS = {'schema', 'status', 'complete', 'entries', 'scanned_entries',
           'ignored_entries', 'read_only', 'registration_performed',
           'activation_performed', 'installation_checked'}


class CatalogCoordinator:
    """The host supplies one fixed folder. Requests cannot replace it.

    One daemon worker and at most one coalesced rerun are retained. Close
    invalidates results; it does not claim to preempt a blocked filesystem call.
    """
    def __init__(self, folder, *, scanner=None, clock=monotonic):
        self._folder = Path(folder)
        self._scanner = scanner or scan_folder
        self._clock = clock
        self._lock = RLock()
        self._generation = 0
        self._running = False
        self._queued = False
        self._closed = False
        self._encoded = None
        self._observed_at = None
        self._started = None
        self._error = None
        self._thread = None

    @property
    def folder(self):
        return self._folder

    def request_scan(self):
        with self._lock:
            if self._closed:
                return self.document()
            self._generation += 1
            self._encoded = None
            self._observed_at = None
            self._error = None
            if self._running:
                self._queued = True
                return self.document()
            self._running = True
            self._started = self._clock()
            worker = Thread(target=self._work, daemon=True, name='AscentWidgetCatalog')
            self._thread = worker
            try:
                worker.start()
            except RuntimeError:
                self._running = False
                self._error = 'CATALOG_SCAN_START_FAILED'
            return self.document()

    @staticmethod
    def _freeze(report):
        if (not isinstance(report, dict) or set(report) != _FIELDS or
                report['schema'] != 'ascent.widget_catalog.v0' or
                report['read_only'] is not True or
                report['registration_performed'] is not False or
                report['activation_performed'] is not False or
                report['installation_checked'] is not False):
            raise ValueError('Unexpected catalog observation')
        encoded = json.dumps(report, allow_nan=False, separators=(',', ':'))
        if len(encoded.encode('utf-8')) > MAX_RESULT_BYTES:
            raise ValueError('Catalog observation exceeds limit')
        return encoded

    def _work(self):
        while True:
            with self._lock:
                if self._closed:
                    self._running = False
                    return
                generation = self._generation
                self._queued = False
                self._started = self._clock()
            encoded = error = None
            try:
                encoded = self._freeze(self._scanner(self._folder))
            except Exception:
                error = 'CATALOG_SCAN_FAILED'
            observed = datetime.now(timezone.utc).isoformat()
            with self._lock:
                if self._closed:
                    self._running = False
                    return
                if generation == self._generation:
                    self._encoded = encoded
                    self._observed_at = observed if encoded is not None else None
                    self._error = error
                    self._running = False
                    return
                # New requests collapse to one latest generation. Never publish
                # the old result while the replacement scan is still pending.

    def document(self):
        with self._lock:
            if self._closed:
                phase = 'CLOSED'
            elif self._running:
                phase = ('SCAN_DELAYED' if self._started is not None and
                         self._clock() - self._started >= SCAN_DELAY_SECONDS else 'SCANNING')
            elif self._error:
                phase = 'FAILED'
            elif self._encoded is not None:
                phase = 'COMPLETE'
            else:
                phase = 'NOT_STARTED'
            return {'schema': 'ascent.widget_catalog_host.v0', 'phase': phase,
                    'generation': self._generation, 'scan_in_progress': self._running,
                    'rescan_queued': self._queued and not self._closed,
                    'observed_at': self._observed_at if not self._closed else None,
                    'result': json.loads(self._encoded) if self._encoded is not None and not self._closed else None,
                    'error': self._error, 'registration_performed': False,
                    'activation_performed': False, 'installation_checked': False}

    def close(self):
        with self._lock:
            self._closed = True
            self._generation += 1
            self._queued = False
            self._encoded = None
            self._observed_at = None
