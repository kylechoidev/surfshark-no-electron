"""Atomic JSON persistence, flock locking, and strict permission verification."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any, Iterator

from surfshark_lite.errors import CredentialsInsecureError


@contextlib.contextmanager
def file_lock(lock_path: Path, non_blocking: bool = False) -> Iterator[int]:
    """Acquire an exclusive flock on lock_path."""
    lock_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if non_blocking else 0)
    try:
        fcntl.flock(fd, flags)
    except BaseException:
        os.close(fd)
        raise
    try:
        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def verify_secure_permissions(path: Path, is_dir: bool = False) -> None:
    """Assert that path is owned by current uid and has no group/other permissions."""
    uid = os.getuid()
    try:
        st = os.lstat(str(path))
    except FileNotFoundError:
        return

    if stat.S_ISLNK(st.st_mode):
        raise CredentialsInsecureError(str(path), f"rm -f {path}")
    if is_dir and not stat.S_ISDIR(st.st_mode):
        raise CredentialsInsecureError(str(path), f"chmod 0700 {path}")
    if not is_dir and not stat.S_ISREG(st.st_mode):
        raise CredentialsInsecureError(str(path), f"chmod 0600 {path}")
    if st.st_uid != uid:
        raise CredentialsInsecureError(str(path), f"chown {uid} {path}")
    if (st.st_mode & 0o077) != 0:
        expected = "0700" if is_dir else "0600"
        raise CredentialsInsecureError(str(path), f"chmod {expected} {path}")


def atomic_write_json(
    path: Path,
    obj: Any,
    mode: int = 0o600,
    lock_path: Path | None = None,
) -> None:
    """Atomically write JSON to path with fsync on file and parent directory."""
    parent = path.parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        parent_st = parent.stat()
        if parent_st.st_uid == os.getuid() and (parent_st.st_mode & 0o077) != 0:
            os.chmod(parent, 0o700)
    except OSError:
        pass

    payload = (json.dumps(obj, indent=2, sort_keys=False) + "\n").encode("utf-8")

    def _do_write() -> None:
        tmp_name = f".{path.name}.{secrets.token_hex(6)}.tmp"
        tmp_path = parent / tmp_name
        fd = os.open(
            str(tmp_path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            mode,
        )
        try:
            os.fchmod(fd, mode)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            try:
                os.unlink(str(tmp_path))
            except OSError:
                pass
            raise
        os.close(fd)
        try:
            os.replace(str(tmp_path), str(path))
            dir_fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            try:
                os.unlink(str(tmp_path))
            except OSError:
                pass
            raise

    if lock_path is not None:
        with file_lock(lock_path):
            _do_write()
    else:
        _do_write()


def read_json_secure(path: Path, check_perms: bool = True) -> dict[str, Any] | None:
    """Read JSON from path, optionally enforcing 0600 file and 0700 directory permissions."""
    if not path.exists() and not path.is_symlink():
        return None

    if check_perms:
        verify_secure_permissions(path.parent, is_dir=True)

    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if check_perms:
            raise CredentialsInsecureError(str(path), f"chmod 0600 {path}") from exc
        raise

    try:
        st = os.fstat(fd)
        if check_perms:
            if not stat.S_ISREG(st.st_mode):
                raise CredentialsInsecureError(str(path), f"chmod 0600 {path}")
            if st.st_uid != os.getuid():
                raise CredentialsInsecureError(str(path), f"chown {os.getuid()} {path}")
            if (st.st_mode & 0o077) != 0:
                raise CredentialsInsecureError(str(path), f"chmod 0600 {path}")
        chunks: list[bytes] = []
        while True:
            buf = os.read(fd, 65536)
            if not buf:
                break
            chunks.append(buf)
        raw = b"".join(chunks).decode("utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("JSON root must be an object")
        return data
    finally:
        os.close(fd)
