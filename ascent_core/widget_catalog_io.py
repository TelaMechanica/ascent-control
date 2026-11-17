"""Read-only folder/file snapshots for catalog discovery; no package execution."""
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import stat


class UnsafeEntry(OSError):
    pass


class ChangedEntry(OSError):
    pass


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _directory_signature(info):
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


def _plain(info, directory=False):
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not expected or getattr(info, 'st_file_attributes', 0) & 0x400 or
            (not directory and info.st_nlink != 1)):
        raise UnsafeEntry('Nonordinary catalog entry')


def _read_fd(fd, limit):
    blocks = []
    remaining = limit + 1
    while remaining:
        block = os.read(fd, min(65536, remaining))
        if not block:
            break
        blocks.append(block)
        remaining -= len(block)
    return b''.join(blocks)


class _PosixFolder:
    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        self.fd = None

    def __enter__(self):
        if (not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd or
                os.scandir not in os.supports_fd):
            raise UnsafeEntry('Safe folder handles unavailable')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
        fd = os.open(self.path.anchor, flags)
        try:
            for part in self.path.parts[1:]:
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            self.fd = fd
            self.initial = os.fstat(fd)
            _plain(self.initial, directory=True)
            self.check()
            return self
        except BaseException:
            os.close(fd)
            self.fd = None
            raise

    def __exit__(self, *args):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def check(self):
        if (_directory_signature(os.fstat(self.fd)) != _directory_signature(self.initial) or
                _directory_signature(self.path.lstat()) != _directory_signature(self.initial)):
            raise ChangedEntry('Catalog folder changed')

    @contextmanager
    def entries(self):
        with os.scandir(self.fd) as entries:
            yield entries

    def stat(self, name):
        return os.stat(name, dir_fd=self.fd, follow_symlinks=False)

    def read(self, name, expected, limit):
        _plain(expected)
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
        try:
            fd = os.open(name, flags, dir_fd=self.fd)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise UnsafeEntry('Unsafe catalog entry') from None
            raise
        try:
            before = os.fstat(fd)
            _plain(before)
            if _signature(before) != _signature(expected):
                raise ChangedEntry('Catalog file changed')
            data = _read_fd(fd, limit)
            if (_signature(os.fstat(fd)) != _signature(before) or
                    _signature(self.stat(name)) != _signature(before)):
                raise ChangedEntry('Catalog file changed')
            return data
        finally:
            os.close(fd)


class _WindowsAPI:
    """Fixed system APIs only. Handles reject reparse points before content reads."""
    def __init__(self):
        import ctypes
        from ctypes import wintypes as w
        self.ctypes = ctypes
        self.w = w
        class Info(ctypes.Structure):
            _fields_ = [('attributes', w.DWORD), ('created', w.FILETIME),
                        ('accessed', w.FILETIME), ('written', w.FILETIME),
                        ('volume', w.DWORD), ('size_high', w.DWORD),
                        ('size_low', w.DWORD), ('links', w.DWORD),
                        ('index_high', w.DWORD), ('index_low', w.DWORD)]
        class Basic(ctypes.Structure):
            _fields_ = [('created', ctypes.c_longlong), ('accessed', ctypes.c_longlong),
                        ('written', ctypes.c_longlong), ('changed', ctypes.c_longlong),
                        ('attributes', w.DWORD)]
        class FileId(ctypes.Structure):
            _fields_ = [('volume', ctypes.c_ulonglong), ('identity', ctypes.c_ubyte * 16)]
        self.Info = Info
        self.Basic = Basic
        self.FileId = FileId
        self.dll = ctypes.WinDLL('kernel32', use_last_error=True, winmode=0x800)
        self.dll.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
        self.dll.CreateFileW.restype = w.HANDLE
        self.dll.CloseHandle.argtypes = [w.HANDLE]
        self.dll.CloseHandle.restype = w.BOOL
        self.dll.GetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.POINTER(Info)]
        self.dll.GetFileInformationByHandle.restype = w.BOOL
        self.dll.GetFileInformationByHandleEx.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
        self.dll.GetFileInformationByHandleEx.restype = w.BOOL
        self.dll.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
        self.dll.GetFinalPathNameByHandleW.restype = w.DWORD
        self.dll.GetFileType.argtypes = [w.HANDLE]
        self.dll.GetFileType.restype = w.DWORD

    def open(self, path, directory=False):
        # OPEN_EXISTING, OPEN_REPARSE_POINT; no delete sharing. Package reads
        # also exclude writers while a snapshot is held.
        flags = 0x00200000 | (0x02000000 if directory else 0)
        handle = self.dll.CreateFileW(str(path), 0x80000000, 3 if directory else 1,
                                     None, 3, flags, None)
        if handle == self.ctypes.c_void_p(-1).value:
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        try:
            info = self.Info()
            if (self.dll.GetFileType(handle) != 1 or
                    not self.dll.GetFileInformationByHandle(handle, self.ctypes.byref(info))):
                raise UnsafeEntry('Non-disk catalog handle')
            if (info.attributes & 0x400 or bool(info.attributes & 0x10) != directory or
                    (not directory and info.links != 1)):
                raise UnsafeEntry('Unsafe catalog handle')
            return handle
        except BaseException:
            self.close(handle)
            raise

    def close(self, handle):
        self.dll.CloseHandle(handle)

    def signature(self, handle):
        info = self.Info()
        basic = self.Basic()
        identity = self.FileId()
        if (not self.dll.GetFileInformationByHandle(handle, self.ctypes.byref(info)) or
                not self.dll.GetFileInformationByHandleEx(handle, 0, self.ctypes.byref(basic), self.ctypes.sizeof(basic)) or
                not self.dll.GetFileInformationByHandleEx(handle, 18, self.ctypes.byref(identity), self.ctypes.sizeof(identity))):
            raise UnsafeEntry('Native catalog metadata unavailable')
        return (identity.volume, bytes(identity.identity), basic.attributes,
                (info.size_high << 32) | info.size_low, info.links,
                basic.created, basic.written, basic.changed)

    def final_path(self, handle):
        import ntpath
        buffer = self.ctypes.create_unicode_buffer(32769)
        length = self.dll.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not 0 < length < len(buffer):
            raise UnsafeEntry('Catalog handle path unavailable')
        value = buffer.value
        if value.startswith('\\\\?\\'):
            value = value[4:]
        if value.startswith('UNC\\') or not ntpath.splitdrive(value)[0].endswith(':'):
            raise UnsafeEntry('Local disk folder required')
        return ntpath.normcase(ntpath.normpath(value))


class _WindowsSnapshot:
    def __init__(self, info, native_signature):
        self.info = info
        self.native_signature = native_signature

    def __getattr__(self, name):
        return getattr(self.info, name)


class _WindowsFolder:
    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        self.handle = None

    def __enter__(self):
        import ntpath
        if not self.path.drive.endswith(':'):
            raise UnsafeEntry('Local disk folder required')
        for path in [*reversed(self.path.parents), self.path]:
            _plain(path.lstat(), directory=True)
        self.initial = self.path.lstat()
        self.api = _WindowsAPI()
        self.handle = self.api.open(self.path, directory=True)
        try:
            self.final = self.api.final_path(self.handle)
            self.native_initial = self.api.signature(self.handle)
            if self.final != ntpath.normcase(ntpath.normpath(str(self.path))):
                raise UnsafeEntry('Catalog folder resolved elsewhere')
            self.check()
            return self
        except BaseException:
            self.api.close(self.handle)
            self.handle = None
            raise

    def __exit__(self, *args):
        if self.handle is not None:
            self.api.close(self.handle)
            self.handle = None

    def check(self):
        if (self.api.final_path(self.handle) != self.final or
                self.api.signature(self.handle) != self.native_initial or
                _directory_signature(self.path.lstat()) != _directory_signature(self.initial)):
            raise ChangedEntry('Catalog folder changed')

    @contextmanager
    def entries(self):
        with os.scandir(self.path) as entries:
            yield entries

    def stat(self, name):
        import ntpath
        self.check()
        path = self.path / name
        info = path.lstat()
        _plain(info)
        handle = self.api.open(path)
        try:
            if self.api.final_path(handle) != ntpath.join(self.final, ntpath.normcase(name)):
                raise UnsafeEntry('Catalog file resolved elsewhere')
            native = self.api.signature(handle)
            if (_signature(path.lstat()) != _signature(info) or
                    native[3] != info.st_size or native[4] != info.st_nlink):
                raise ChangedEntry('Catalog file changed')
            return _WindowsSnapshot(info, native)
        finally:
            self.api.close(handle)

    def read(self, name, expected, limit):
        import msvcrt
        import ntpath
        _plain(expected)
        self.check()
        handle = self.api.open(self.path / name)
        fd = None
        try:
            if self.api.final_path(handle) != ntpath.join(self.final, ntpath.normcase(name)):
                raise UnsafeEntry('Catalog file resolved elsewhere')
            native_before = self.api.signature(handle)
            if native_before != expected.native_signature:
                raise ChangedEntry('Catalog file changed')
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None  # fd now owns the handle.
            before = os.fstat(fd)
            _plain(before)
            data = _read_fd(fd, limit)
            current = self.stat(name)
            if (_signature(os.fstat(fd)) != _signature(before) or
                    self.api.signature(msvcrt.get_osfhandle(fd)) != native_before or
                    current.native_signature != native_before or
                    _signature(current.info) != _signature(expected.info)):
                raise ChangedEntry('Catalog file changed')
            self.check()
            return data
        finally:
            if fd is not None:
                os.close(fd)
            elif handle is not None:
                self.api.close(handle)


def open_folder(path):
    return _WindowsFolder(path) if os.name == 'nt' else _PosixFolder(path)
