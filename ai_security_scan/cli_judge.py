"""Optional, bounded transports to officially installed subscription CLIs.

The installed executable, its authentication store and administrator policy are
trusted. No repository is used as a CLI working directory and no credentials are
read or copied by this module. CLI capability restrictions are not an OS sandbox.
"""

import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata


CLI_PROVIDERS = {"codex_cli", "claude_cli", "grok_cli"}
DEFAULT_CLI_MODELS = {"codex_cli": "gpt-6-astra", "claude_cli": "opus", "grok_cli": "grok-build"}
_COMMANDS = {"codex_cli": "codex", "claude_cli": "claude", "grok_cli": "grok"}
_MINIMUM = {"codex_cli": (0, 154, 0), "claude_cli": (2, 1, 214), "grok_cli": (0, 2, 60)}
_LIMIT = 5 * 1024 * 1024
_DIAGNOSTIC_LIMIT = 64 * 1024
_CODEX_DISABLED_WARNING = ("Code Mode is unavailable because code-mode host is disabled. "
                           "Code mode will fail closed; enable `features.code_mode_host` "
                           "and install `codex-code-mode-host`.")
_CODEX_DISABLED = (
    "shell_tool", "unified_exec", "code_mode", "code_mode_host", "computer_use",
    "browser_use", "browser_use_external", "browser_use_full_cdp_access",
    "in_app_browser", "image_generation", "view_image", "artifact", "apps",
    "plugins", "plugin_sharing", "hooks", "multi_agent", "multi_agent_v2",
    "skill_search", "workspace_dependencies", "shell_snapshot", "memories",
    "sleep_tool", "goals", "remote_plugin", "tool_suggest",
)
_ENV_ALLOW = {
    "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR",
    "PATH", "TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL", "USER", "LOGNAME",
    "CODEX_HOME", "CLAUDE_CONFIG_DIR", "GROK_HOME", "HTTPS_PROXY", "HTTP_PROXY",
    "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SSL_CERT_FILE",
    "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
}


class CLIJudgeError(Exception):
    """Sanitized configuration, process or protocol error."""


class CLIJudgeAuthError(CLIJudgeError):
    """The official CLI explicitly reported missing or expired authentication."""


def _text(value, label, maximum=4096):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(unicodedata.category(c).startswith("C") for c in value)):
        raise CLIJudgeError("CLI judge {} must be nonempty text without control characters.".format(label))
    return value


def validate_cli_config(config):
    """Return a canonical strict configuration without starting a CLI."""
    if not isinstance(config, dict) or config.get("provider") not in CLI_PROVIDERS:
        raise CLIJudgeError("CLI judge provider must be codex_cli, claude_cli or grok_cli.")
    allowed = {"provider", "model", "executable", "timeout_seconds", "max_request_bytes",
               "max_response_bytes", "cli_home"}
    if set(config) - allowed:
        raise CLIJudgeError("CLI judge configuration contains unsupported fields; arbitrary arguments, API fields and token budgets are not accepted.")
    result = dict(config)
    result["model"] = _text(result.get("model", DEFAULT_CLI_MODELS[result["provider"]]), "model", 256)
    if result["model"].startswith("-"):
        raise CLIJudgeError("CLI judge model must not begin with an option prefix.")
    executable = _text(result.get("executable", _COMMANDS[result["provider"]]), "executable")
    if executable.startswith("-") or (not Path(executable).is_absolute() and not re.fullmatch(r"[A-Za-z0-9_.-]+", executable)):
        raise CLIJudgeError("CLI judge executable must be an absolute path or a bare command name.")
    if Path(executable).suffix.lower() in {".bat", ".cmd", ".ps1"}:
        raise CLIJudgeError("CLI judge requires a native executable, not a shell command file.")
    result["executable"] = executable
    for key, default, low, high, integral in (
            ("timeout_seconds", 60, 0.1, 300, False),
            ("max_request_bytes", 524288, 1024, _LIMIT, True),
            ("max_response_bytes", 1048576, 1024, _LIMIT, True)):
        value = result.get(key, default)
        types = (int,) if integral else (int, float)
        if isinstance(value, bool) or not isinstance(value, types) or not math.isfinite(value) or not low <= value <= high:
            raise CLIJudgeError("CLI judge configuration has an invalid numeric limit.")
        result[key] = value
    if "cli_home" in result:
        value = _text(result["cli_home"], "cli_home")
        if result["provider"] != "grok_cli" or not Path(value).is_absolute():
            raise CLIJudgeError("cli_home is supported only as an absolute existing Grok home directory.")
    return result


def _loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("nonfinite")

    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        # Reject lone surrogate strings and non-finite floats, including 1e999.
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise CLIJudgeError("CLI judge returned invalid or ambiguous JSON.") from None


def _executable(config):
    candidate = config["executable"]
    if not Path(candidate).is_absolute():
        # Never resolve a bare executable through '.' or a relative PATH entry.
        entries = [p for p in os.environ.get("PATH", "").split(os.pathsep)
                   if p and Path(p).is_absolute() and Path(p).resolve() != Path.cwd().resolve()]
        candidate = shutil.which(candidate, path=os.pathsep.join(entries))
    if not candidate or not Path(candidate).is_file() or not os.access(candidate, os.X_OK):
        raise CLIJudgeError("The selected CLI judge executable is not installed or executable.")
    if Path(candidate).suffix.lower() in {".bat", ".cmd", ".ps1"}:
        raise CLIJudgeError("CLI judge requires a native executable, not a shell command file.")
    return str(Path(candidate).absolute())


def _environment(config):
    environment = {k: v for k, v in os.environ.items() if k in _ENV_ALLOW}
    environment.update({"NO_COLOR": "1", "TERM": "dumb", "CI": "1"})
    if config["provider"] == "claude_cli":
        environment.update({"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"})
    if config["provider"] == "grok_cli":
        if "cli_home" in config:
            home_dir = Path(config["cli_home"])
            if not home_dir.is_dir() or home_dir.is_symlink():
                raise CLIJudgeError("CLI judge cli_home must be an existing nonsymlink directory; sign in using the official CLI separately.")
            environment["GROK_HOME"] = str(home_dir)
        environment.update({"GROK_DISABLE_AUTOUPDATER": "1", "GROK_TELEMETRY_ENABLED": "false",
                            "GROK_TRACE_UPLOAD": "false", "GROK_MEMORY": "0", "GROK_SUBAGENTS": "0",
                            "GROK_WEB_FETCH": "0", "GROK_RELAY_SYNC_ENABLED": "false"})
    return environment


def _stop(process):
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _auth_failure(raw):
    text = raw.decode("utf-8", "replace").lower()
    return bool(re.search(r"not logged in|authentication required|oauth[^\n]{0,100}(?:expired|invalid)|invalid[_ ]api[_ ]key|please (?:log|sign) in", text))


def _run(argv, *, cwd, environment, stdin=b"", deadline, limit, include_stderr=False, allowed_exit_codes=(0,)):
    """Bounded pipes and wall time; diagnostics never reach logs or reports."""
    if time.monotonic() >= deadline:
        raise CLIJudgeError("CLI judge exceeded its timeout.")
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=environment, shell=False,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0, close_fds=True,
                                   start_new_session=(os.name == "posix"))
    except (OSError, ValueError):
        raise CLIJudgeError("CLI judge could not be started.") from None
    events = queue.Queue(maxsize=4)
    stopping = threading.Event()

    def publish(value):
        while not stopping.is_set():
            try:
                events.put(value, timeout=0.02)
                break
            except queue.Full:
                continue

    def read(pipe, kind, cap):
        used = 0
        try:
            while not stopping.is_set():
                data = pipe.read(min(65536, cap - used + 1))
                if not data:
                    break
                used += len(data)
                if used > cap:
                    publish(("error", "CLI judge {} exceeded its byte limit.".format(kind)))
                    return
                publish(("data" if kind == "output" else "diagnostic", data))
        except (OSError, ValueError):
            publish(("error", "CLI judge output could not be read."))
        finally:
            publish(("done", kind))

    def write():
        try:
            view = memoryview(stdin)
            while view and not stopping.is_set():
                count = process.stdin.write(view[:65536])
                if not count:
                    break
                view = view[count:]
        except (OSError, ValueError):
            pass  # A process rejecting its arguments may close stdin immediately.
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    workers = [threading.Thread(target=read, args=(process.stdout, "output", limit), daemon=True),
               threading.Thread(target=read, args=(process.stderr, "diagnostics", _DIAGNOSTIC_LIMIT), daemon=True),
               threading.Thread(target=write, daemon=True)]
    for worker in workers:
        worker.start()
    chunks, diagnostics = [], []
    completed = set()
    try:
        while len(completed) < 2 or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CLIJudgeError("CLI judge exceeded its timeout.")
            try:
                kind, value = events.get(timeout=min(0.05, remaining))
            except queue.Empty:
                continue
            if kind == "error":
                raise CLIJudgeError(value)
            if kind == "data":
                chunks.append(value)
            elif kind == "diagnostic":
                diagnostics.append(value)
            elif kind == "done":
                completed.add(value)
        if process.returncode not in allowed_exit_codes:
            if _auth_failure(b"".join(chunks + diagnostics)):
                raise CLIJudgeAuthError("CLI sign-in is missing or expired. Run invarune --login with the selected provider, or use an interactive scan for automatic login.")
            raise CLIJudgeError("CLI judge failed; check official CLI sign-in, subscription limits, model availability and required flags.")
        return b"".join(chunks + diagnostics if include_stderr else chunks)
    finally:
        stopping.set()
        # Also kill descendants when their parent exits successfully.
        _stop(process)
        for worker in workers:
            worker.join(timeout=0.2)
        for pipe in (process.stdin, process.stdout, process.stderr):
            try:
                pipe.close()
            except OSError:
                pass


def _probe(executable, provider, cwd, environment, deadline):
    raw = _run([executable, "--version"], cwd=cwd, environment=environment,
               deadline=deadline, limit=_DIAGNOSTIC_LIMIT)
    patterns = {"codex_cli": rb"codex-cli (\d+)\.(\d+)\.(\d+)",
                "claude_cli": rb"(\d+)\.(\d+)\.(\d+) \(Claude Code\)",
                "grok_cli": rb"grok (\d+)\.(\d+)\.(\d+)"}
    match = re.match(patterns[provider], raw.strip())
    if not match or tuple(int(part) for part in match.groups()) < _MINIMUM[provider]:
        raise CLIJudgeError("CLI judge version is unsupported; update the official CLI to the documented minimum version.")
    version = ".".join(part.decode("ascii") for part in match.groups())
    command = [executable, "exec", "--help"] if provider == "codex_cli" else [executable, "--help"]
    help_text = _run(command, cwd=cwd, environment=environment, deadline=deadline, limit=_DIAGNOSTIC_LIMIT)
    required = {
        "codex_cli": ["--ignore-user-config", "--ignore-rules", "--ephemeral", "--json", "--sandbox", "--disable", "--output-schema"],
        "claude_cli": ["--safe-mode", "--tools", "--strict-mcp-config", "--no-session-persistence", "--output-format", "--permission-mode", "--json-schema", "--effort"],
        "grok_cli": ["--prompt-file", "--tools", "--deny", "--permission-mode", "--no-subagents", "--no-memory", "--disable-web-search", "--disallowed-tools"],
    }[provider]
    if any(flag.encode("ascii") not in help_text for flag in required):
        raise CLIJudgeError("CLI judge lacks required capability restriction flags; update the official CLI.")
    return version


def probe_auth(config):
    """Ask official status commands; never inspect credential files or identities.

    Grok has no documented authentication-status command. Its state is unknown
    until inference or the explicit official login flow completes.
    """
    config = validate_cli_config(config)
    executable, environment = _executable(config), _environment(config)
    with tempfile.TemporaryDirectory(prefix="invarune-auth-") as temporary:
        directory = Path(temporary).resolve()
        deadline = time.monotonic() + min(config["timeout_seconds"], 30)
        _probe(executable, config["provider"], directory, environment, deadline)
        if config["provider"] == "grok_cli":
            _grok_preflight(executable, directory, environment, deadline)
            return {"logged_in": None, "verification": "no_vendor_status_command"}
        command = [executable, "login", "status"] if config["provider"] == "codex_cli" else [executable, "auth", "status"]
        raw = _run(command, cwd=directory, environment=environment, deadline=deadline,
                   limit=_DIAGNOSTIC_LIMIT, allowed_exit_codes=(0, 1), include_stderr=config["provider"] == "codex_cli")
        if config["provider"] == "claude_cli":
            data = _loads(raw)
            if not isinstance(data, dict) or not isinstance(data.get("loggedIn"), bool):
                raise CLIJudgeError("Claude authentication status could not be verified.")
            return {"logged_in": data["loggedIn"], "verification": "official_cli_status"}
        text = raw.decode("utf-8", "replace").strip()
        if text == "Logged in using ChatGPT" or text.startswith("Logged in using an API key"):
            return {"logged_in": True, "verification": "official_cli_status"}
        if text == "Not logged in":
            return {"logged_in": False, "verification": "official_cli_status"}
        raise CLIJudgeError("Codex authentication status could not be verified.")


def login_cli(config, timeout_seconds=300):
    """Delegate interactive OAuth to the vendor; resume only after success.

    The official flow owns browser/device authorization and its credential store.
    Nothing from this interactive flow is captured in a scan report or log.
    """
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise CLIJudgeError("CLI login needs an interactive terminal. Run invarune --login with the selected provider in a terminal.")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or not 1 <= timeout_seconds <= 900:
        raise CLIJudgeError("CLI login timeout must be finite and between 1 and 900 seconds.")
    config = validate_cli_config(config)
    executable, environment = _executable(config), _environment(config)
    environment.pop("CI", None)
    environment["TERM"] = os.environ.get("TERM", "xterm-256color")
    with tempfile.TemporaryDirectory(prefix="invarune-login-") as temporary:
        directory = Path(temporary).resolve()
        deadline = time.monotonic() + timeout_seconds
        _probe(executable, config["provider"], directory, environment, deadline)
        if config["provider"] == "grok_cli":
            _grok_preflight(executable, directory, environment, deadline)
        args = {"codex_cli": ["login"], "claude_cli": ["auth", "login", "--claudeai"], "grok_cli": ["login", "--oauth"]}[config["provider"]]
        try:
            process = subprocess.Popen([executable, *args], cwd=directory, env=environment,
                                       stdin=sys.stdin, stdout=sys.stderr, stderr=sys.stderr,
                                       shell=False, close_fds=True)
        except (OSError, ValueError):
            raise CLIJudgeError("Official CLI login could not start.") from None
        try:
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if code != 0:
                raise CLIJudgeAuthError("Official CLI login did not complete; deterministic results are preserved.")
        except subprocess.TimeoutExpired:
            raise CLIJudgeAuthError("Official CLI login timed out; deterministic results are preserved.") from None
        except KeyboardInterrupt:
            raise CLIJudgeAuthError("Official CLI login was cancelled; deterministic results are preserved.") from None
        finally:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                raise CLIJudgeError("Official login process did not finish cleanup within its deadline.") from None
    if config["provider"] != "grok_cli" and probe_auth(config)["logged_in"] is not True:
        raise CLIJudgeAuthError("Official CLI login finished but sign-in could not be verified.")
    return {"logged_in": True, "verification": "official_login_completed"}


def _grok_preflight(executable, cwd, environment, deadline):
    raw = _run([executable, "--cwd", str(cwd), "inspect", "--json"], cwd=cwd,
               environment=environment, deadline=deadline, limit=1024 * 1024)
    inspected = _loads(raw)
    fields = ("hooks", "mcpServers", "lspServers", "plugins", "skills", "projectInstructions", "agents", "marketplaces")
    if not isinstance(inspected, dict) or any(not isinstance(inspected.get(k), list) for k in fields):
        raise CLIJudgeError("Grok CLI inspection output is incompatible; extension isolation cannot be verified.")
    active = []
    for key in fields:
        for entry in inspected[key]:
            if not isinstance(entry, dict):
                raise CLIJudgeError("Grok CLI inspection output is incompatible.")
            source = entry.get("source")
            builtin = source == "builtin" or (isinstance(source, dict) and source.get("type") == "builtin")
            if entry.get("disabled") is True or entry.get("enabled") is False or entry.get("scope") == "builtin" or builtin:
                continue
            active.append(key)
            break
    if active:
        raise CLIJudgeError("Grok CLI has active extensions or external instructions ({}). Use a dedicated clean GROK_HOME signed in with the official CLI; no credentials are copied by Invarune.".format(", ".join(active)))


def _schema(stage):
    def obj(properties):
        return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}
    string = {"type": "string"}
    if stage == "findings":
        return obj({"assessments": {"type": "array", "items": obj({
            "finding_id": string, "verdict": {"type": "string", "enum": ["likely_true_positive", "likely_false_positive", "needs_review"]},
            "reason": string})}, "additional_concerns": {"type": "array", "items": string}})
    check = obj({"check_index": {"type": "integer"}, "status": {"type": "string", "enum": [
        "supported_by_code", "potential_gap", "needs_runtime_validation", "needs_human_review", "insufficient_evidence", "not_applicable_proposed"]},
        "reason": string, "citations": {"type": "array", "items": obj({"evidence_id": string, "quote": string})},
        "verification_steps": {"type": "array", "items": string}})
    return obj({"control_assessments": {"type": "array", "items": obj({"control_id": string,
                "check_assessments": {"type": "array", "items": check}})}})


def _write_private(path, data):
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except OSError:
        raise CLIJudgeError("CLI judge could not create a private request file.") from None


def _command(executable, provider, directory, model, prompt, stage="findings"):
    if provider == "codex_cli":
        argv = [executable, "-a", "never", "exec", "--ignore-user-config", "--ignore-rules",
                "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json", "--color", "never"]
        for feature in _CODEX_DISABLED:
            argv += ["--disable", feature]
        for setting in ("web_search=\"disabled\"", "mcp_servers={}", "project_doc_max_bytes=0", "skills.include_instructions=false", 'model_reasoning_effort="high"'):
            argv += ["-c", setting]
        schema_path = directory / "response-schema.json"
        _write_private(schema_path, json.dumps(_schema(stage)).encode("utf-8"))
        argv += ["--output-schema", str(schema_path)]
        if model != "default":
            argv += ["--model", model]
        return argv + ["-"], prompt
    if provider == "claude_cli":
        argv = [executable, "--print", "--safe-mode", "--output-format", "json", "--tools", "",
                "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--permission-mode", "dontAsk",
                "--no-session-persistence", "--no-chrome", "--disable-slash-commands", "--setting-sources", "", "--effort", "high",
                "--json-schema", json.dumps(_schema(stage), separators=(",", ":"))]
        if model != "default":
            argv += ["--model", model]
        return argv, prompt
    path = directory / "request.txt"
    _write_private(path, prompt)
    argv = [executable, "--prompt-file", str(path), "--output-format", "json", "--cwd", str(directory),
            "--tools", "Bash", "--disallowed-tools", "run_terminal_cmd,bash,search_tool,use_tool",
            "--deny", "*", "--permission-mode", "dontAsk",
            "--disable-web-search", "--no-subagents", "--no-memory", "--max-turns", "1", "--sandbox", "read-only"]
    if model != "default":
        argv += ["--model", model]
    return argv, b""


def _extract(provider, raw, warnings=None):
    if provider == "codex_cli":
        events = [_loads(line) for line in raw.splitlines() if line.strip()]
        messages = []
        completed = False
        started = False
        for event in events:
            if not isinstance(event, dict):
                raise CLIJudgeError("Codex CLI returned an invalid event envelope.")
            kind = event.get("type")
            if completed:
                raise CLIJudgeError("Codex CLI emitted activity after its completed turn.")
            if kind in {"thread.started", "turn.started"}:
                if started:
                    raise CLIJudgeError("Codex CLI emitted a duplicate or reordered turn.")
                started = started or kind == "turn.started"
                continue
            if kind == "turn.completed":
                if not started or not messages:
                    raise CLIJudgeError("Codex CLI completed without an active advisory response.")
                completed = True
            elif kind in {"item.started", "item.updated", "item.completed"}:
                item = event.get("item", {})
                # The CLI emits this exact warning before the turn when our
                # deliberately disabled Code Mode host is selected by a model.
                # It is not a model tool call or a failed turn. No other error
                # message is accepted, and warning text is never exported.
                if (not started and isinstance(item, dict) and kind == "item.completed"
                        and item.get("type") == "error" and item.get("message") == _CODEX_DISABLED_WARNING):
                    if warnings is not None:
                        warnings.append("codex_code_mode_intentionally_disabled")
                    continue
                if not isinstance(item, dict) or item.get("type") not in {"agent_message", "reasoning"}:
                    raise CLIJudgeError("Codex CLI emitted a tool or unsupported activity event; advisory response rejected.")
                if not started:
                    raise CLIJudgeError("Codex CLI emitted advice before its turn started.")
                if kind == "item.completed" and item.get("type") == "agent_message":
                    messages.append(item.get("text"))
            else:
                raise CLIJudgeError("Codex CLI did not complete a bounded advisory response.")
        if not completed or not messages or not isinstance(messages[-1], str):
            raise CLIJudgeError("Codex CLI returned no completed advisory response.")
        return _loads(messages[-1])
    envelope = _loads(raw)
    if not isinstance(envelope, dict):
        raise CLIJudgeError("CLI judge returned an invalid response envelope.")
    if any(envelope.get(key) for key in ("tool_calls", "tool_use", "permission_denials", "error", "errors", "is_error")):
        if _auth_failure(raw.encode("utf-8") if isinstance(raw, str) else raw):
            raise CLIJudgeAuthError("CLI sign-in is missing or expired. Use invarune --login or an interactive scan to sign in directly.")
        raise CLIJudgeError("CLI judge reported an error or tool activity; advisory response rejected.")
    if provider == "claude_cli":
        if envelope.get("type") != "result" or envelope.get("subtype") != "success" or envelope.get("is_error") is not False:
            raise CLIJudgeError("Claude CLI did not return a successful advisory result.")
        content = envelope.get("structured_output", envelope.get("result"))
    else:
        if envelope.get("stopReason") != "end_turn":
            raise CLIJudgeError("Grok CLI did not complete its advisory response.")
        content = envelope.get("text")
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        raise CLIJudgeError("CLI judge returned no JSON advisory content.")
    return _loads(content)


def run_cli(config, payload, instructions, stage="findings"):
    """Run one explicitly enabled advisory request, returning data and audit metadata.

    Caller must validate exact finding/control IDs and citations independently.
    Windows currently terminates only the direct process; use an external job or
    container boundary for equivalent descendant lifecycle isolation.
    """
    config = validate_cli_config(config)
    if stage not in {"findings", "controls"} or not isinstance(instructions, str):
        raise CLIJudgeError("CLI judge received an invalid review stage or instructions.")
    try:
        serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False)
        prompt = (instructions + "\n\nUNTRUSTED EVIDENCE JSON:\n" + serialized).encode("utf-8")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise CLIJudgeError("CLI judge payload is not valid UTF-8 JSON.") from None
    if len(prompt) > config["max_request_bytes"]:
        raise CLIJudgeError("CLI judge request exceeded its byte limit.")
    executable = _executable(config)
    environment = _environment(config)
    deadline = time.monotonic() + config["timeout_seconds"]
    with tempfile.TemporaryDirectory(prefix="invarune-judge-") as temporary:
        directory = Path(temporary).resolve()
        version = _probe(executable, config["provider"], directory, environment, deadline)
        if config["provider"] == "grok_cli":
            _grok_preflight(executable, directory, environment, deadline)
        argv, stdin = _command(executable, config["provider"], directory, config["model"], prompt, stage)
        raw = _run(argv, cwd=directory, environment=environment, stdin=stdin,
                   deadline=deadline, limit=config["max_response_bytes"])
        warnings = []
        output = _extract(config["provider"], raw, warnings)
        if not isinstance(output, dict):
            raise CLIJudgeError("CLI judge response must be a JSON object.")
        safe_arguments = [value.replace(str(directory), "<private temporary directory>") for value in argv[1:]]
    return output, {"transport": "official_cli", "provider": config["provider"], "cli_version": version,
                    "executable": Path(executable).name, "requested_model": config["model"],
                    "auth_mode": "cli_managed", "stage": stage, "arguments": safe_arguments,
                    "request_sha256": hashlib.sha256(prompt).hexdigest(), "request_bytes": len(prompt),
                    "response_sha256": hashlib.sha256(raw).hexdigest(), "response_bytes": len(raw),
                    "repository_working_directory": False, "tools_policy": "disabled_for_advisory_review",
                    "isolation": "CLI capability restrictions; installed executable and administrator policy remain trusted",
                    "descendant_termination": "process_group" if os.name == "posix" else "direct_process_only",
                    "token_budget_enforced": False, "startup_warnings": warnings,
                    "structured_output_requested": config["provider"] != "grok_cli"}
