"""Bounded acquisition of a local Docker/Podman image, without running it.

The runtime executable and its configured daemon/connection are trusted inputs.
No image is pulled unless explicitly requested. Only ``image pull`` and
``image save`` are invoked; exported data is validated by the archive reader.
"""

import math
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unicodedata


_CHUNK_BYTES = 64 * 1024
_DIAGNOSTIC_BYTES = 64 * 1024
_PLATFORM = re.compile(r"[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*){0,2}\Z")


class ImageRuntimeError(ValueError):
    """A runtime request failed without disclosing its potentially secret output."""


def _stop_process(process):
    # The session is ours on POSIX, including any runtime credential helpers.
    # On Windows Popen.kill terminates the directly invoked runtime process.
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run(command, stream, *, max_stdout_bytes, deadline, operation, runtime):
    """Drain both pipes concurrently, with bounded memory, I/O and elapsed time.

    A small bounded queue transfers stdout to the writing thread. Stderr is
    counted and discarded, never interpolated into errors. Both pipes are
    drained even when one is idle, including on Windows (no pipe selectors).
    """
    if time.monotonic() >= deadline:
        raise ImageRuntimeError("Image acquisition exceeded its timeout")
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False, bufsize=0,
            start_new_session=(os.name == "posix"),
        )
    except (OSError, ValueError):
        raise ImageRuntimeError("The selected image runtime could not be started") from None

    chunks = queue.Queue(maxsize=2)
    failures = queue.Queue(maxsize=2)
    stop = threading.Event()
    stderr_done = threading.Event()

    def record_failure(reason):
        try:
            failures.put_nowait(reason)
        except queue.Full:
            pass

    def put_chunk(chunk):
        while not stop.is_set():
            try:
                chunks.put(chunk, timeout=0.05)
                return
            except queue.Full:
                continue

    def read_stdout():
        try:
            while not stop.is_set():
                chunk = process.stdout.read(min(_CHUNK_BYTES, max_stdout_bytes + 1))
                if not chunk:
                    break
                put_chunk(chunk)
        except (OSError, ValueError):
            if not stop.is_set():
                record_failure("Image runtime output could not be read")
        finally:
            put_chunk(None)

    def read_stderr():
        consumed = 0
        try:
            while not stop.is_set():
                chunk = process.stderr.read(min(_CHUNK_BYTES, _DIAGNOSTIC_BYTES - consumed + 1))
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > _DIAGNOSTIC_BYTES:
                    record_failure("Image runtime diagnostic output exceeded its 64 KiB limit")
                    break
        except (OSError, ValueError):
            if not stop.is_set():
                record_failure("Image runtime diagnostics could not be read")
        finally:
            stderr_done.set()

    workers = [threading.Thread(target=read_stdout, daemon=True),
               threading.Thread(target=read_stderr, daemon=True)]
    written = 0
    complete = False
    for worker in workers:
        worker.start()
    try:
        stdout_done = False
        while True:
            if time.monotonic() >= deadline:
                raise ImageRuntimeError("Image acquisition exceeded its timeout")
            try:
                failure = failures.get_nowait()
            except queue.Empty:
                failure = None
            if failure:
                raise ImageRuntimeError(failure)
            if stdout_done and stderr_done.is_set() and process.poll() is not None:
                # Recheck after observing completion: the reader publishes its
                # failure before setting stderr_done, so it cannot be lost.
                try:
                    raise ImageRuntimeError(failures.get_nowait())
                except queue.Empty:
                    break
            try:
                chunk = chunks.get(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if chunk is None:
                stdout_done = True
            else:
                if written + len(chunk) > max_stdout_bytes:
                    label = "archive" if stream is not None else "informational output"
                    raise ImageRuntimeError("Image runtime {} exceeded its byte limit".format(label))
                if stream is not None:
                    stream.write(chunk)
                written += len(chunk)
        if process.returncode != 0:
            if operation == "pull":
                message = "{} image pull failed; check registry access and runtime configuration"
            else:
                message = "{} image export failed; check that the runtime is running and the image exists locally"
            raise ImageRuntimeError(message.format(runtime.capitalize()))
        if stream is not None and written == 0:
            raise ImageRuntimeError("Image runtime returned an empty archive")
        complete = True
    finally:
        stop.set()
        if not complete:
            _stop_process(process)
        for pipe in (process.stdout, process.stderr):
            pipe.close()
        for worker in workers:
            worker.join(timeout=0.2)


def export_image(reference, destination: Path, *, runtime="docker", pull=False,
                 platform=None, max_archive_bytes=2_000_000_000, timeout_seconds=300):
    """Atomically save one image to a Docker archive, never start a container.

    The timeout covers the entire optional pull plus export. Archive writes
    never exceed max_archive_bytes; stdout/stderr informational streams each
    have a 64 KiB limit. A failed request removes its private temporary file and
    leaves any prior destination unchanged. A pull can populate the runtime's
    own image store; that store is managed and bounded by the runtime, not this
    archive-writing limit.

    Docker accepts --platform for save (API 1.48+). Podman save does not expose
    that flag: platform is passed to an explicit pull, and the caller must
    validate/select the resulting platform through the archive reader.
    """
    if runtime not in ("docker", "podman"):
        raise ImageRuntimeError("Image runtime must be docker or podman")
    if (not isinstance(reference, str) or not reference or len(reference) > 4096
            or reference.startswith("-") or any(c.isspace() or unicodedata.category(c).startswith("C") for c in reference)):
        raise ImageRuntimeError("Image reference must be nonempty and contain no whitespace, control characters or leading option")
    if platform is not None and (not isinstance(platform, str) or not _PLATFORM.fullmatch(platform)):
        raise ImageRuntimeError("Image platform must use os[/architecture[/variant]] syntax")
    if not isinstance(pull, bool):
        raise ImageRuntimeError("The image pull option must be a boolean")
    if isinstance(max_archive_bytes, bool) or not isinstance(max_archive_bytes, int) or max_archive_bytes <= 0:
        raise ImageRuntimeError("The image archive byte limit must be a positive integer")
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
        raise ImageRuntimeError("The image acquisition timeout must be a positive finite number")
    executable = shutil.which(runtime)
    if not executable:
        raise ImageRuntimeError("{} is not installed or is not available on PATH".format(runtime.capitalize()))
    if Path(executable).suffix.lower() in {".bat", ".cmd"}:
        raise ImageRuntimeError("The image runtime must be a native executable, not a shell command file")
    destination = Path(destination)
    if destination.is_symlink():
        raise ImageRuntimeError("The image archive destination must not be a symbolic link")
    deadline = time.monotonic() + timeout_seconds
    temporary_path = None
    try:
        if pull:
            command = [executable, "image", "pull", "--quiet"]
            if platform:
                command += ["--platform", platform]
            command += ["--", reference]
            _run(command, None, max_stdout_bytes=_DIAGNOSTIC_BYTES, deadline=deadline,
                 operation="pull", runtime=runtime)
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".ai-image-", suffix=".tar.part",
                                         dir=destination.parent, delete=False) as output:
            temporary_path = Path(output.name)
            command = [executable, "image", "save"]
            if runtime == "podman":
                command += ["--format", "docker-archive", "--quiet"]
            elif platform:
                command += ["--platform", platform]
            command += ["--", reference]
            _run(command, output, max_stdout_bytes=max_archive_bytes, deadline=deadline,
                 operation="export", runtime=runtime)
        if time.monotonic() >= deadline:
            raise ImageRuntimeError("Image acquisition exceeded its timeout")
        os.replace(temporary_path, destination)
        temporary_path = None
    except (OSError, ValueError) as exc:
        if isinstance(exc, ImageRuntimeError):
            raise
        raise ImageRuntimeError("The image archive could not be written to its destination") from None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
    return {"reference": reference, "runtime": runtime, "pulled": pull, "platform": platform}
