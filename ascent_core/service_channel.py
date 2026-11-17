"""Short-lived source/interface-bound TCP channel for trusted SSH operations.

No command API, key material, default route fallback or widget access. The only
listener is task-owned loopback; the upstream endpoint comes from selected context.
"""
from contextlib import contextmanager
import ipaddress
import os
import select
import socket
import struct
from threading import Event, Thread
import time
from .service_access import AccessDenied

IP_UNICAST_IF = 31  # Winsock; interface index is supplied in network byte order.
LOOPBACK = str(ipaddress.IPv4Address(0x7f000001))


def windows_source_socket(target, check, *, socket_factory=socket.socket):
    """Caller invokes only on Windows. Tests use an injected socket, not hardware."""
    if type(target.interface_index) is not int or not 0 < target.interface_index < 2**24:
        raise AccessDenied('RECEIVER_INTERFACE_REQUIRED')
    check()
    stream = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
    try:
        stream.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack('!I', target.interface_index))
        stream.bind((target.source_ip, 0))
        stream.settimeout(2)
        check()
        stream.connect((target.host, 22))
        check()
        return stream
    except Exception:
        stream.close()
        raise


class SelectedSshChannel:
    def __init__(self, *, connector=None):
        self._connector = connector

    @contextmanager
    def open(self, target, check):
        if self._connector is None and os.name != 'nt':
            raise AccessDenied('WINDOWS_RECEIVER_TRANSPORT_REQUIRED')
        check()
        stop = Event()
        sockets = []
        failure = []
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == 'nt': listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind((LOOPBACK, 0)); listener.listen(1); listener.settimeout(.2)
        deadline = time.monotonic() + 8
        def live_check():
            if stop.is_set() or time.monotonic() >= deadline:
                raise AccessDenied('RECEIVER_CHANNEL_EXPIRED')
            check()
            if stop.is_set() or time.monotonic() >= deadline:
                raise AccessDenied('RECEIVER_CHANNEL_EXPIRED')
        def relay():
            try:
                while not stop.is_set() and time.monotonic() < deadline:
                    try: client, _ = listener.accept(); break
                    except socket.timeout: continue
                else: return
                sockets.append(client)
                live_check()
                upstream = (self._connector(target, live_check) if self._connector is not None
                            else windows_source_socket(target, live_check))
                sockets.append(upstream)
                client.settimeout(1); upstream.settimeout(1)
                while not stop.is_set() and time.monotonic() < deadline:
                    live_check()
                    ready, _, _ = select.select([client, upstream], [], [], .1)
                    for source in ready:
                        data = source.recv(16384)
                        if not data: return
                        live_check()
                        (upstream if source is client else client).sendall(data)
            except Exception as error:
                # Keep only a stable category; socket exceptions can contain paths/IPs.
                failure.append('RECEIVER_BINDING_CHANGED' if isinstance(error, AccessDenied) else 'RECEIVER_CHANNEL_FAILED')
            finally:
                for stream in sockets:
                    try: stream.close()
                    except OSError: pass
        thread = Thread(target=relay, daemon=True)
        thread.start()
        try:
            yield LOOPBACK, listener.getsockname()[1]
            check()
            if failure: raise AccessDenied(failure[0])
        finally:
            stop.set(); listener.close()
            for stream in sockets:
                try: stream.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                stream.close()
            thread.join(timeout=3)
            if thread.is_alive(): raise AccessDenied('RECEIVER_CHANNEL_STOP_FAILED')
