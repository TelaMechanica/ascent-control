"""Transport contracts and current widget operation requirements, without private access code.

This records existing capabilities, not Core/Pro product policy. An installed bridge
and host administrator rights never imply private receiver shell access.
"""
from __future__ import annotations
import caddx_fw_version as fwver
from enum import Enum
from typing import Protocol


class AccessKind(str, Enum):
    HOST_LOCAL = 'host_local'
    HOST_ADMIN = 'host_admin'
    VENDOR_PROTOCOL = 'vendor_protocol'
    INSTALLED_BRIDGE = 'installed_bridge'
    PRIVATE_RECEIVER = 'private_receiver'
    AUTONOMOUS_RUNTIME = 'autonomous_runtime'


class ReceiverTransport(Protocol):
    def run(self, command: str, **kwargs) -> dict: ...
    def upload(self, path, remote_name: str) -> dict: ...


class ReceiverSession(Protocol):
    device_id: str
    state: str
    transport: ReceiverTransport
    def connect(self) -> dict: ...
    def end(self) -> None: ...


class ReceiverAccessProvider(Protocol):
    def acquire(self) -> tuple[ReceiverSession | None, str | None]: ...


# Current implementations only. Mapster deploy's private preflight is deliberately
# retained until pending/resume + UI trust semantics can change together.
_WIDGET_OPERATIONS = {
    'picker': {'draft': AccessKind.HOST_LOCAL, 'inspect': AccessKind.PRIVATE_RECEIVER,
               'select': AccessKind.PRIVATE_RECEIVER, 'configure': AccessKind.PRIVATE_RECEIVER,
               'install': AccessKind.PRIVATE_RECEIVER, 'remove': AccessKind.PRIVATE_RECEIVER,
               'run': AccessKind.AUTONOMOUS_RUNTIME},
    'netrunner': {'inspect': AccessKind.PRIVATE_RECEIVER, 'configure': AccessKind.PRIVATE_RECEIVER,
                 'install': AccessKind.PRIVATE_RECEIVER, 'remove': AccessKind.PRIVATE_RECEIVER},
    'mapster': {'build': AccessKind.HOST_LOCAL, 'inspect': AccessKind.INSTALLED_BRIDGE,
                'clear': AccessKind.INSTALLED_BRIDGE, 'layout': AccessKind.INSTALLED_BRIDGE,
                'deploy': AccessKind.PRIVATE_RECEIVER, 'install': AccessKind.PRIVATE_RECEIVER,
                'remove_runtime': AccessKind.PRIVATE_RECEIVER},
}


def requirement(widget: str, operation: str) -> AccessKind:
    """Unknown operations raise, rather than defaulting to an available capability."""
    return _WIDGET_OPERATIONS[widget][operation]


def lifecycle_document() -> dict:
    return {widget: {op: kind.value for op, kind in operations.items()}
            for widget, operations in _WIDGET_OPERATIONS.items()}


def video_document(identity=None):
    """Firmware-presence evidence, never current subtype/flag/service truth."""
    identity=identity or {}
    name=str(identity.get('device_name') or '').lower()
    fw=fwver.parse(identity.get('firmware'))
    maximum='vrx_max' in name
    pro='vrx_pro' in name
    qualified=(maximum and fw in {(19,2,4),(19,2,14)}) or (pro and fw==(18,21,10))
    return dict(scope='static_reference_firmware' if qualified else 'unqualified_reference',
        rtsp_stack='SmolRTSP' if qualified else None,
        stock_rtsp_start_condition='board product_type / --subtype ==1' if qualified else None,
        current_board_subtype=None,rtsp_listening=None,
        uvc_code_present=True if qualified else None,uvc_factory_gate='stSetDev.uvc_enable ==1' if qualified else None,
        uvc_enabled=None,uvc_streaming=None,uvc_rtsp_concurrency='hardware_unverified',
        wifi_driver='AIC8800' if qualified and maximum else 'RTL8189FU' if qualified and pro else None,
        wifi_stock_boot='startup script commented out' if qualified else None,
        note='Endpoint templates and firmware code presence do not prove a listening server, enabled UVC, fitted hardware or concurrent performance.')
