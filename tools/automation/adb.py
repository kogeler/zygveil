# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

"""ADB selection and command boundary."""

from __future__ import annotations

import hashlib
import re
import shlex
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from reporting import CheckError, Report


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str


@dataclass(frozen=True)
class DeviceUiState:
    wakefulness: str
    window_awake: bool
    keyguard_showing: bool

    @property
    def ready(self) -> bool:
        return self.wakefulness == "Awake" and self.window_awake and not self.keyguard_showing


def join_shell_arguments(arguments: Sequence[str]) -> str:
    if not arguments:
        raise CheckError("ADB shell command is empty")
    return shlex.join(arguments)


def shell_argument_self_test() -> None:
    vectors = (
        ("/system/bin/id", "-u"),
        ("/system/bin/sh", "-c", 'set -eu; IFS= read -r value; test -n "$value"'),
        ("printf", "%s\\n", "space separated", "single'quote", 'double"quote'),
        ("printf", "%s", "", "line one\nline two"),
    )
    for arguments in vectors:
        command = join_shell_arguments(arguments)
        if shlex.split(command) != list(arguments):
            raise CheckError("ADB shell argument quoting self-test failed")


def parse_adb_devices(output: str) -> dict[str, str]:
    devices: dict[str, str] = {}
    for raw_line in output.replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("List of devices attached") or line.startswith("*"):
            continue
        fields = line.split()
        if len(fields) < 2 or fields[0] in devices:
            raise CheckError("ADB transport inventory is malformed")
        devices[fields[0]] = fields[1]
    return devices


def choose_adb_selector(devices: dict[str, str], requested: str) -> tuple[str, str]:
    if requested:
        if devices.get(requested) != "device":
            raise CheckError("the requested ADB transport is absent, offline, or unauthorized")
        return requested, "explicit"
    if not devices:
        raise CheckError("no ADB transport is present")
    if len(devices) > 1:
        raise CheckError("multiple ADB transports are present; pass ADB_SERIAL explicitly")
    serial, state = next(iter(devices.items()))
    if state != "device":
        raise CheckError("the only ADB transport is offline or unauthorized")
    return serial, "implicit_single"


def device_selection_self_test() -> None:
    single = parse_adb_devices("List of devices attached\nselector-a\tdevice\n")
    if choose_adb_selector(single, "") != ("selector-a", "implicit_single"):
        raise CheckError("single-transport ADB selection self-test failed")
    multiple = parse_adb_devices(
        "List of devices attached\nselector-a\tdevice\nselector-b\toffline\n"
    )
    if choose_adb_selector(multiple, "selector-a") != ("selector-a", "explicit"):
        raise CheckError("explicit ADB selection self-test failed")
    for devices, requested in ((multiple, ""), (single, "selector-b"), ({}, "")):
        try:
            choose_adb_selector(devices, requested)
        except CheckError as error:
            if "selector-" in str(error):
                raise CheckError("ADB selection failure exposed a selector") from error
        else:
            raise CheckError("ADB selection negative self-test failed")


def parse_device_ui_state(power: str, window: str) -> DeviceUiState:
    wakefulness = re.findall(
        r"^\s+mWakefulness=(Awake|Asleep|Dozing|Dreaming)\s*$", power, re.MULTILINE
    )
    window_awake = re.findall(r"^\s+mAwake=(true|false)\b", window, re.MULTILINE)
    keyguard_showing = re.findall(r"^\s+isKeyguardShowing=(true|false)\s*$", window, re.MULTILINE)
    if len(wakefulness) != 1 or len(window_awake) != 1 or len(keyguard_showing) != 1:
        raise CheckError("device UI readiness state is unavailable or ambiguous")
    return DeviceUiState(
        wakefulness=wakefulness[0],
        window_awake=window_awake[0] == "true",
        keyguard_showing=keyguard_showing[0] == "true",
    )


def device_ui_state_self_test() -> None:
    ready = parse_device_ui_state(
        "  mWakefulness=Awake\nmWakefulness=1\n",
        "    mAwake=true mScreenOnEarly=true\n    isKeyguardShowing=false\n",
    )
    if not ready.ready:
        raise CheckError("device UI ready-state self-test failed")
    locked = parse_device_ui_state(
        "  mWakefulness=Dozing\nmWakefulness=3\n",
        "    mAwake=false mScreenOnEarly=false\n    isKeyguardShowing=true\n",
    )
    if locked.ready or locked.wakefulness != "Dozing" or not locked.keyguard_showing:
        raise CheckError("device UI locked-state self-test failed")
    for power, window in (
        ("mWakefulness=1\n", "    mAwake=true\n    isKeyguardShowing=false\n"),
        ("  mWakefulness=Awake\n", "    mAwake=true\n"),
        (
            "  mWakefulness=Awake\n",
            "    mAwake=true\n    mAwake=false\n    isKeyguardShowing=false\n",
        ),
    ):
        try:
            parse_device_ui_state(power, window)
        except CheckError:
            pass
        else:
            raise CheckError("device UI parser negative self-test failed")


def read_device_ui_state(adb: Adb) -> DeviceUiState:
    power = adb.shell("dumpsys", "power", timeout=30, check=False)
    window = adb.shell("dumpsys", "window", timeout=30, check=False)
    if power.returncode != 0 or window.returncode != 0:
        raise CheckError("device UI readiness services are unavailable")
    return parse_device_ui_state(power.stdout, window.stdout)


def wait_for_device_ui_state(adb: Adb, *, seconds: float) -> DeviceUiState:
    deadline = time.monotonic() + seconds
    state = read_device_ui_state(adb)
    while not state.ready and time.monotonic() < deadline:
        time.sleep(0.25)
        state = read_device_ui_state(adb)
    return state


def ensure_device_ui_ready(adb: Adb, report: Report) -> DeviceUiState:
    try:
        initial = read_device_ui_state(adb)
    except CheckError as error:
        report.kv("ui_ready", "false")
        report.kv("ui_readiness_result", "manual_unlock_required")
        raise CheckError(
            "manual_unlock_required: cannot prove display/keyguard state; "
            "unlock the phone and rerun the same target"
        ) from error

    report.kv("ui_initial_wakefulness", initial.wakefulness)
    report.kv("ui_initial_window_awake", str(initial.window_awake).lower())
    report.kv("ui_initial_keyguard_showing", str(initial.keyguard_showing).lower())
    actions: list[str] = []
    state = initial
    if state.wakefulness != "Awake" or not state.window_awake:
        wake = adb.shell("input", "keyevent", "KEYCODE_WAKEUP", timeout=10, check=False)
        if wake.returncode != 0:
            report.kv("ui_ready", "false")
            report.kv("ui_readiness_result", "manual_unlock_required")
            raise CheckError(
                "manual_unlock_required: automation could not wake the display; "
                "unlock the phone and rerun the same target"
            )
        actions.append("wake_display")
        state = wait_for_device_ui_state(adb, seconds=3.0)

    if state.keyguard_showing:
        dismiss = adb.shell("wm", "dismiss-keyguard", timeout=10, check=False)
        if dismiss.returncode == 0:
            actions.append("dismiss_noncredential_keyguard")
            state = wait_for_device_ui_state(adb, seconds=3.0)

    report.kv("ui_readiness_actions", ",".join(actions) if actions else "none")
    report.kv("ui_final_wakefulness", state.wakefulness)
    report.kv("ui_final_window_awake", str(state.window_awake).lower())
    report.kv("ui_final_keyguard_showing", str(state.keyguard_showing).lower())
    report.kv("ui_ready", str(state.ready).lower())
    if not state.ready:
        report.kv("ui_readiness_result", "manual_unlock_required")
        raise CheckError(
            "manual_unlock_required: credential-protected keyguard remains; "
            "unlock the phone and rerun the same target"
        )
    report.kv("ui_readiness_result", "ready")
    return state


def system_server_process_identity(adb: Adb) -> tuple[str, str]:
    def read_pid() -> str:
        result = adb.shell("pidof", "system_server", check=False)
        pids = result.stdout.split()
        if result.returncode != 0 or len(pids) != 1 or not pids[0].isdigit():
            raise CheckError("system_server PID is unavailable or ambiguous")
        return pids[0]

    def read_start_ticks(pid: str) -> str:
        result = adb.shell("cat", f"/proc/{pid}/stat", timeout=10, check=False)
        body = result.stdout.strip()
        command_end = body.rfind(")")
        fields = body[command_end + 2 :].split() if command_end >= 0 else []
        if result.returncode != 0 or len(fields) < 20 or not fields[19].isdigit():
            raise CheckError("system_server start-time identity is unavailable")
        return fields[19]

    pid = read_pid()
    start_ticks = read_start_ticks(pid)
    if read_pid() != pid or read_start_ticks(pid) != start_ticks:
        raise CheckError("system_server identity changed during inspection")
    return pid, start_ticks


def installed_apk_sha256(adb: Adb, package: str) -> str:
    paths = adb.shell("pm", "path", package, check=False)
    candidates = [
        line.removeprefix("package:").strip()
        for line in paths.stdout.splitlines()
        if line.startswith("package:")
    ]
    base = next((path for path in candidates if path.endswith("/base.apk")), None)
    if paths.returncode != 0 or base is None:
        raise CheckError(f"installed base APK path is unavailable: {package}")
    with tempfile.TemporaryDirectory(prefix="zygveil-installed-") as directory:
        destination = Path(directory) / "base.apk"
        pull = adb.run("pull", base, str(destination), timeout=120, check=False)
        if pull.returncode != 0 or not destination.is_file():
            raise CheckError(f"could not pull installed base APK: {package}")
        return hashlib.sha256(destination.read_bytes()).hexdigest()


class Adb:
    def __init__(self, serial: str, report: Report) -> None:
        self.serial = serial
        self.report = report
        self.prefix = ["adb", "-s", serial]

    @classmethod
    def select(cls, requested_serial: str, report: Report) -> Adb:
        result = subprocess.run(
            ["adb", "devices"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=15,
        )
        if result.returncode != 0:
            raise CheckError(f"adb devices failed with {result.returncode}")
        devices = parse_adb_devices(result.stdout)
        serial, selection_mode = choose_adb_selector(devices, requested_serial)

        adb = cls(serial, report)
        state = adb.run("get-state", timeout=10).stdout.strip()
        if state != "device":
            raise CheckError(f"unexpected ADB state: {state}")
        report.section("adb-transport")
        report.kv("transport_count", len(devices))
        report.kv("selection_mode", selection_mode)
        report.kv("adb_state", state)
        return adb

    def run(self, *arguments: str, timeout: int = 30, check: bool = True) -> CommandResult:
        try:
            completed = subprocess.run(
                [*self.prefix, *arguments],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise CheckError(f"ADB command timed out after {timeout}s") from error
        output = completed.stdout.replace("\r", "").replace(self.serial, "<adb-selector>")
        if check and completed.returncode != 0:
            raise CheckError(f"ADB command failed with {completed.returncode}: {output.strip()}")
        return CommandResult(completed.returncode, output)

    def run_input(
        self, *arguments: str, input_text: str, timeout: int = 30, check: bool = True
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                [*self.prefix, *arguments],
                check=False,
                input=input_text,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise CheckError(f"ADB stdin command timed out after {timeout}s") from None
        output = completed.stdout.replace("\r", "")
        if check and completed.returncode != 0:
            raise CheckError(f"ADB stdin command failed with {completed.returncode}")
        return CommandResult(completed.returncode, output)

    def shell(self, *arguments: str, timeout: int = 30, check: bool = True) -> CommandResult:
        return self.run("shell", *arguments, timeout=timeout, check=check)

    def shell_input(
        self, *arguments: str, input_text: str, timeout: int = 30, check: bool = True
    ) -> CommandResult:
        command = join_shell_arguments(arguments)
        return self.run_input("shell", command, input_text=input_text, timeout=timeout, check=check)

    def getprop(self, key: str) -> str:
        return self.shell("getprop", key).stdout.strip()
