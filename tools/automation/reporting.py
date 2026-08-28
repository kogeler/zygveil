# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

"""Atomic, minimal evidence reports for Make-wrapped automation."""

from __future__ import annotations

import math
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Literal, TextIO


class CheckError(RuntimeError):
    """A validated command or evidence contract failed."""


def redact_local_paths(value: str) -> str:
    candidates: dict[str, str] = {}
    for label, candidate in (("<checkout>", Path.cwd()), ("<home>", Path.home())):
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        text = resolved.as_posix().rstrip("/")
        if text:
            candidates[text] = label
    redacted = value
    for path, label in sorted(candidates.items(), key=lambda item: len(item[0]), reverse=True):
        redacted = redacted.replace(path, label)
    return redacted


def local_path_redaction_self_test() -> None:
    value = f"{Path.cwd()}/candidate {Path.home()}/private"
    redacted = redact_local_paths(value)
    if Path.cwd().as_posix() in redacted or Path.home().as_posix() in redacted:
        raise CheckError("local path redaction self-test failed")


class DeferredPrivateText:
    """Stage one private artifact and publish it only after its report closes."""

    def __init__(self) -> None:
        self._pending: tuple[Path, Path] | None = None

    def stage(self, destination: Path, content: str) -> None:
        if self._pending is not None:
            raise CheckError("a private evidence artifact is already pending")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".pending", dir=destination.parent
        )
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            self._pending = (temporary, destination)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
            raise

    def commit(self) -> None:
        if self._pending is None:
            return
        temporary, destination = self._pending
        os.replace(temporary, destination)
        self._pending = None

    def discard(self) -> None:
        if self._pending is None:
            return
        temporary, _destination = self._pending
        temporary.unlink(missing_ok=True)
        self._pending = None


def deferred_private_text_self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="zygveil-deferred-private-self-test-") as directory:
        destination = Path(directory) / "phase.json"
        writer = DeferredPrivateText()
        writer.stage(destination, "first\n")
        if destination.exists():
            raise CheckError("pending private artifact was published before report close")
        writer.commit()
        if (
            destination.read_text(encoding="utf-8") != "first\n"
            or stat.S_IMODE(destination.stat().st_mode) != 0o600
        ):
            raise CheckError("deferred private artifact commit self-test failed")
        writer.stage(destination, "second\n")
        writer.discard()
        if destination.read_text(encoding="utf-8") != "first\n":
            raise CheckError("discarded private artifact replaced accepted evidence")


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def contains_private_decimal_values(content: str, values: Iterable[str]) -> bool:
    """Detect privacy-distinctive decimal inputs in arbitrary serialized evidence."""
    for value in values:
        if re.fullmatch(r"-?[0-9]+\.[0-9]+", value) is None:
            continue
        candidates = {value}
        normalized = value.rstrip("0").rstrip(".")
        if "." in normalized:
            candidates.add(normalized)
        binary64 = float(value)
        if math.isfinite(binary64):
            round_trip = format(binary64, ".17g")
            if "." in round_trip or "e" in round_trip.lower():
                candidates.add(round_trip)
        for candidate in candidates:
            if re.search(rf"(?<![0-9.]){re.escape(candidate)}(?![0-9.])", content):
                return True
    return False


class Report:
    def __init__(self, directory: Path, name: str) -> None:
        self.directory = directory
        self.name = name
        self.path = directory / f"{name}.txt"
        self._temporary: Path | None = None
        self._stream: TextIO | None = None
        self._started = utc_now()

    def __enter__(self) -> Report:
        self.directory.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.name}.", suffix=".tmp", dir=self.directory
        )
        self._temporary = Path(temporary)
        self._stream = os.fdopen(descriptor, "w", encoding="utf-8")
        self.kv("report", self.name)
        self.kv("started_utc", self._started)
        return self

    def __exit__(
        self,
        error_type: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        status = 0 if error is None else 1
        if error is not None:
            self.kv("error", str(error).replace("\n", " "))
        self.line()
        self.kv("finished_utc", utc_now())
        self.kv("exit_status", status)
        assert self._stream is not None
        assert self._temporary is not None
        self._stream.flush()
        os.fsync(self._stream.fileno())
        self._stream.close()
        os.replace(self._temporary, self.path)
        try:
            destination = self.path.relative_to(Path.cwd()).as_posix()
        except ValueError:
            destination = self.path.name
        print(f"{'PASS' if status == 0 else 'FAIL'} {destination}")
        return False

    def line(self, value: str = "") -> None:
        assert self._stream is not None
        self._stream.write(f"{redact_local_paths(value)}\n")

    def section(self, value: str) -> None:
        self.line()
        self.line(f"[{value}]")

    def kv(self, key: str, value: object) -> None:
        normalized = str(value).replace("\r", "").replace("\n", "\\n")
        self.line(f"{key}={normalized}")

    def assert_redacted(
        self,
        patterns: Iterable[str],
        predicates: Iterable[Callable[[str], bool]] = (),
    ) -> None:
        assert self._stream is not None
        assert self._temporary is not None
        self._stream.flush()
        content = self._temporary.read_text(encoding="utf-8")
        pattern_list = tuple(patterns)
        predicate_list = tuple(predicates)
        matched_pattern = next(
            (
                index
                for index, pattern in enumerate(pattern_list)
                if re.search(pattern, content, re.IGNORECASE)
            ),
            None,
        )
        matched_predicate = next(
            (index for index, predicate in enumerate(predicate_list) if predicate(content)),
            None,
        )
        if matched_pattern is None and matched_predicate is None:
            self.kv("redaction_check", "pass")
            return

        self._stream.close()
        self._temporary.unlink(missing_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.name}.", suffix=".tmp", dir=self.directory
        )
        self._temporary = Path(temporary)
        self._stream = os.fdopen(descriptor, "w", encoding="utf-8")
        self.kv("report", self.name)
        self.kv("started_utc", self._started)
        self.kv("redaction_check", "failed; unsafe candidate report discarded")
        failure_class = (
            f"pattern_{matched_pattern}"
            if matched_pattern is not None
            else f"predicate_{matched_predicate}"
        )
        self.kv("redaction_failure_class", failure_class)
        raise CheckError(f"report redaction check failed: {failure_class}")
