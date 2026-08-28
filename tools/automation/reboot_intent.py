# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

"""Durable, privacy-safe reboot intent shared by supported device state machines."""

from __future__ import annotations

import contextlib
import fcntl
import functools
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]
INTENT_DIR = ROOT / ".artifacts/state/reboot-intents"
TRANSITION_LOCK = INTENT_DIR / ".transition.lock"
INTENT_KEYS = {
    "schema_version",
    "operation",
    "expected_state",
    "context_id",
    "source_boot_id_sha256",
    "source_system_server_pid",
    "source_system_server_start_ticks",
}


def intent_path(name: str) -> Path:
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is None:
        raise CheckError("reboot intent name is invalid")
    return INTENT_DIR / f"{name}.json"


def ensure_intent_directory(path: Path, *, create: bool) -> bool:
    directory = path.parent
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError as error:
            raise CheckError("reboot intent directory mode could not be secured") from error
    try:
        identity = directory.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise CheckError("reboot intent directory identity is unavailable") from error
    if (
        not stat.S_ISDIR(identity.st_mode)
        or stat.S_ISLNK(identity.st_mode)
        or stat.S_IMODE(identity.st_mode) != 0o700
        or identity.st_uid != os.getuid()
    ):
        raise CheckError("reboot intent directory identity is invalid")
    return True


def sync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    except OSError as error:
        raise CheckError("reboot intent directory could not be opened durably") from error
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def reject_conflicting_intents(path: Path) -> None:
    if not ensure_intent_directory(path, create=False):
        return
    try:
        conflicts = sorted(
            candidate.name
            for candidate in path.parent.iterdir()
            if candidate != path and candidate.name.endswith(".json")
        )
    except OSError as error:
        raise CheckError("pending reboot intent inventory is unavailable") from error
    if conflicts:
        raise CheckError("a different reboot-bearing transition is still pending")


@contextmanager
def transition_lock() -> Iterator[None]:
    ensure_intent_directory(TRANSITION_LOCK, create=True)
    try:
        descriptor = os.open(
            TRANSITION_LOCK,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as error:
        raise CheckError("reboot transition lock could not be opened safely") from error
    try:
        identity = os.fstat(descriptor)
        if (
            not stat.S_ISREG(identity.st_mode)
            or stat.S_IMODE(identity.st_mode) != 0o600
            or identity.st_uid != os.getuid()
            or identity.st_nlink != 1
        ):
            raise CheckError("reboot transition lock identity is invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CheckError("another reboot-bearing transition is already running") from None
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def serialized_transition[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        with transition_lock():
            return function(*args, **kwargs)

    return wrapped


def write_intent(path: Path, values: dict[str, object]) -> None:
    ensure_intent_directory(path, create=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(values, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def validate_intent(
    values: dict[str, object],
    *,
    operation: str,
    expected_state: str,
    context_id: str,
) -> None:
    source_boot = values.get("source_boot_id_sha256")
    source_pid = values.get("source_system_server_pid")
    source_ticks = values.get("source_system_server_start_ticks")
    if (
        set(values) != INTENT_KEYS
        or type(values.get("schema_version")) is not int
        or values.get("schema_version") != 2
        or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", operation) is None
        or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", expected_state) is None
        or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", context_id) is None
        or values.get("operation") != operation
        or values.get("expected_state") != expected_state
        or values.get("context_id") != context_id
        or not isinstance(source_boot, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_boot) is None
        or not isinstance(source_pid, str)
        or re.fullmatch(r"[0-9]{1,20}", source_pid) is None
        or not isinstance(source_ticks, str)
        or re.fullmatch(r"[0-9]{1,20}", source_ticks) is None
    ):
        raise CheckError("pending reboot intent does not match the requested transition")


def load_intent(
    path: Path,
    *,
    operation: str,
    expected_state: str,
    context_id: str,
) -> dict[str, object] | None:
    reject_conflicting_intents(path)
    try:
        path_identity = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CheckError("pending reboot intent identity is unavailable") from error
    if stat.S_ISLNK(path_identity.st_mode) or not stat.S_ISREG(path_identity.st_mode):
        raise CheckError("pending reboot intent identity is invalid")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise CheckError("pending reboot intent could not be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= 4096
        ):
            raise CheckError("pending reboot intent identity is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024))
            if not block:
                raise CheckError("pending reboot intent changed while being read")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise CheckError("pending reboot intent changed while being read")
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
        )
        if tuple(getattr(before, field) for field in stable_fields) != tuple(
            getattr(after, field) for field in stable_fields
        ):
            raise CheckError("pending reboot intent changed while being read")
    finally:
        os.close(descriptor)
    try:
        raw = b"".join(chunks).decode("utf-8")
        decoded: object = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CheckError("pending reboot intent is unreadable") from error
    if not isinstance(decoded, dict):
        raise CheckError("pending reboot intent is not an object")
    values = cast(dict[str, object], decoded)
    validate_intent(
        values,
        operation=operation,
        expected_state=expected_state,
        context_id=context_id,
    )
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n"
    if raw != canonical:
        raise CheckError("pending reboot intent is not canonical")
    return values


def begin_or_resume(
    report: Report,
    path: Path,
    *,
    operation: str,
    expected_state: str,
    context_id: str,
    current_boot_id_sha256: str,
    current_system_server_pid: str,
    current_system_server_start_ticks: str,
) -> tuple[dict[str, object], bool]:
    existing = load_intent(
        path,
        operation=operation,
        expected_state=expected_state,
        context_id=context_id,
    )
    if existing is None:
        values: dict[str, object] = {
            "schema_version": 2,
            "operation": operation,
            "expected_state": expected_state,
            "context_id": context_id,
            "source_boot_id_sha256": current_boot_id_sha256,
            "source_system_server_pid": current_system_server_pid,
            "source_system_server_start_ticks": current_system_server_start_ticks,
        }
        validate_intent(
            values,
            operation=operation,
            expected_state=expected_state,
            context_id=context_id,
        )
        write_intent(path, values)
        existing = values
    resumed = existing["source_boot_id_sha256"] != current_boot_id_sha256
    if not resumed and (
        existing["source_system_server_pid"] not in {"0", current_system_server_pid}
        or existing["source_system_server_start_ticks"]
        not in {"0", current_system_server_start_ticks}
    ):
        raise CheckError("system_server changed within the pending reboot source boot")
    report.kv("reboot_intent", "resumed_new_boot" if resumed else "prepared_source_boot")
    report.kv("reboot_source_boot_id_sha256", existing["source_boot_id_sha256"])
    report.kv("reboot_resumed", str(resumed).lower())
    return existing, resumed


def clear_intent(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        raise CheckError("pending reboot intent could not be removed") from error
    if path.parent.exists():
        sync_directory(path.parent)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="zygveil-reboot-intent-self-test-") as directory:
        path = Path(directory) / "intent.json"
        values: dict[str, object] = {
            "schema_version": 2,
            "operation": "location-reboot",
            "expected_state": "active",
            "context_id": "location",
            "source_boot_id_sha256": "a" * 64,
            "source_system_server_pid": "123",
            "source_system_server_start_ticks": "456",
        }
        write_intent(path, values)
        loaded = load_intent(
            path,
            operation="location-reboot",
            expected_state="active",
            context_id="location",
        )
        if loaded != values or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise CheckError("reboot intent round-trip self-test failed")
        try:
            load_intent(
                path,
                operation="location-reboot",
                expected_state="disabled",
                context_id="location",
            )
        except CheckError:
            pass
        else:
            raise CheckError("reboot intent mismatch self-test failed")
        path.chmod(0o644)
        try:
            load_intent(
                path,
                operation="location-reboot",
                expected_state="active",
                context_id="location",
            )
        except CheckError:
            pass
        else:
            raise CheckError("reboot intent mode self-test failed")
        path.chmod(0o600)
        other = path.parent / "other.json"
        write_intent(other, dict(values, operation="location-recover"))
        try:
            load_intent(
                path,
                operation="location-reboot",
                expected_state="active",
                context_id="location",
            )
        except CheckError:
            pass
        else:
            raise CheckError("reboot intent single-flight self-test failed")
        other.unlink()
        path.unlink()
        path.symlink_to("missing.json")
        try:
            load_intent(
                path,
                operation="location-reboot",
                expected_state="active",
                context_id="location",
            )
        except CheckError:
            pass
        else:
            raise CheckError("reboot intent no-follow self-test failed")
