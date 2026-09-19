"""Offline, deterministic source analysis. Never imports or executes target code.

Python rules use the syntax tree and simple local source tracking. JS/TS and YAML
rules are deliberately bounded lexical checks. JSON config rules traverse parsed
objects. Findings identify reviewable evidence, not whole-program vulnerability
proofs. Unsupported dynamic configuration needs manual review.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .rules import RULE_BY_ID


_SOURCE_SUFFIXES = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_CONFIG_SUFFIXES = {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"}
_SECRET_KEY = re.compile(r"(?:^|[_-])(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|private[_-]?key)(?:$|[_-])", re.I)
_SECRET_CAMEL = re.compile(r"^(?:apiKey|accessToken|authToken|clientSecret|secretKey|password|passwd|privateKey)$")
_EXTERNAL_NAMES = {"user_input", "user_url", "user_path", "user_query", "user_prompt", "user_content", "tool_input", "tool_args", "tool_output", "tool_result", "request_data", "request_body", "request", "req", "payload", "event"}
_AUTH_DISABLED = {"auth", "authentication", "requireauth", "requireauthentication", "enableauth", "authenabled", "authenticationenabled", "verifyauth"}
_WILDCARD_PERMISSION_KEYS = {"allowedtools", "toolallowlist", "permissions", "allowtools", "allowedoperations", "allow", "scopes", "allowedresources"}
_PASSTHROUGH_KEYS = {"tokenpassthrough", "allowtokenpassthrough", "forwardaccesstoken", "forwardauthorization", "passthroughtoken"}


def _norm(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _is_secret_key(value):
    return bool(_SECRET_KEY.search(value) or _SECRET_CAMEL.match(value) or value.lower() in {"token", "secret"})


def _placeholder(value):
    """Keep explicit examples out without suppressing realistically shaped secrets."""
    if not isinstance(value, str) or not value.strip():
        return True
    value = value.strip()
    lowered = value.lower()
    if len(value) < 8:
        return True
    if re.match(r"^(?:\$\{|\$[A-Z_]|<|\{\{|%[A-Z_])", value):
        return True
    if lowered in {"your_api_key", "your-api-key", "redacted", "placeholder", "example-token", "example-key", "test-token", "test-secret", "dummy-secret", "your-token-here", "sk-your-key-here"}:
        return True
    if re.fullmatch(r"(?:x+|\*+|\.+|0+)", value, re.I):
        return True
    if lowered.startswith(("replace_me", "replace-me", "your_api_key_here", "your-api-key-here", "example_", "dummy_")):
        return True
    return False


def _constant(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _is_literal(node):
    return isinstance(node, ast.Constant)


def _interpolated(node):
    return isinstance(node, (ast.JoinedStr, ast.BinOp)) or (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format")


def _has_star(value):
    if value == "*" or value == "all":
        return True
    if isinstance(value, (list, tuple)):
        return any(_has_star(item) for item in value)
    if isinstance(value, dict):
        return any(_has_star(item) for item in value.values())
    return False


def _unrestricted_approval(value):
    return value is True or isinstance(value, (list, tuple)) and "*" in value


def _unpinned_package(value):
    if not isinstance(value, str) or value.startswith(("-", ".", "/", "file:", "workspace:")):
        return False
    if "==" in value:
        return not bool(re.search(r"==\d+(?:\.\d+)+(?:[a-zA-Z0-9.+-]*)$", value))
    if "@" in value[1:]:
        version = value.rsplit("@", 1)[1]
        return not bool(re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", version))
    return True


def _remote_http(value):
    if not isinstance(value, str) or not value.lower().startswith("http://"):
        return False
    try:
        host = urlsplit(value).hostname or ""
    except ValueError:
        return True
    return host.lower() not in {"localhost", "127.0.0.1", "::1"} and not host.startswith("127.")


def _strip_comments(text):
    """Mask JS/JSONC comments while preserving strings, newlines, and offsets."""
    output = list(text)
    index = 0
    quote = None
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ('"', "'", "`"):
            quote = char
            index += 1
            continue
        if text[index:index + 2] == "//":
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            output[index:end] = " " * (end - index)
            index = end
            continue
        if text[index:index + 2] == "/*":
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            for offset in range(index, end):
                if text[offset] != "\n":
                    output[offset] = " "
            index = end
            continue
        index += 1
    return "".join(output)


class _Findings:
    def __init__(self, path, text):
        self.path = path
        self.text = text
        self.lines = text.splitlines()
        self.items = []
        self.seen = set()

    def add(self, rule_id, line, end_line=None, confidence="medium", detail=None):
        line = max(1, int(line))
        key = (rule_id, line)
        if key in self.seen:
            return
        self.seen.add(key)
        end_line = max(line, int(end_line or line))
        metadata = RULE_BY_ID[rule_id]
        result = {key: metadata[key] for key in ("title", "severity", "description", "remediation", "category", "cwe", "references")}
        result.update(rule_id=rule_id, confidence=confidence, path=self.path,
                      line=line, end_line=end_line,
                      evidence="\n".join(self.lines[line - 1:min(end_line, line + 2)])[:1000])
        if detail:
            result["description"] += " " + detail
        self.items.append(result)

    def offset(self, rule_id, start, end=None, confidence="medium", detail=None):
        self.add(rule_id, self.text.count("\n", 0, start) + 1,
                 self.text.count("\n", 0, end if end is not None else start) + 1,
                 confidence, detail)


class _PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, findings):
        self.findings = findings
        self.aliases = {}
        self.external_scopes = [set()]
        self.object_types = {}

    def name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self.name(node.value) + "." + node.attr
        return ""

    def add(self, rule_id, node, confidence="medium", detail=None):
        self.findings.add(rule_id, node.lineno, getattr(node, "end_lineno", node.lineno), confidence, detail)

    def external(self, node):
        if node is None:
            return False
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            if name in {"input", "sys.stdin.read", "sys.stdin.readline"}:
                return True
            if name.startswith(("request.", "req.", "flask.request.")):
                return True
        if isinstance(node, ast.Name):
            return node.id in _EXTERNAL_NAMES or any(node.id in scope for scope in self.external_scopes)
        return any(self.external(child) for child in ast.iter_child_nodes(node))

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = node.module + "." + alias.name

    def visit_FunctionDef(self, node):
        # Track assignment-derived sources locally; do not leak local taint between functions.
        old_aliases = self.aliases.copy()
        old_types = self.object_types.copy()
        self.external_scopes.append(set())
        self.generic_visit(node)
        self.external_scopes.pop()
        self.aliases = old_aliases
        self.object_types = old_types

    visit_AsyncFunctionDef = visit_FunctionDef

    def _track_object(self, target, value):
        if not isinstance(target, ast.Name):
            return
        if isinstance(value, ast.Call):
            constructor = self.name(value.func)
            known_types = {"requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession", "tarfile.open", "zipfile.ZipFile"}
            if constructor in known_types:
                self.object_types[target.id] = constructor
                return
        self.object_types.pop(target.id, None)

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars is not None:
                self._track_object(item.optional_vars, item.context_expr)
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def _assignment(self, target, value, node):
        self._track_object(target, value)
        name = self.name(target)
        if isinstance(target, ast.Name):
            if self.external(value):
                self.external_scopes[-1].add(target.id)
            else:
                self.external_scopes[-1].discard(target.id)
        key = name.rsplit(".", 1)[-1]
        if isinstance(target, ast.Subscript):
            literal_key = _constant(target.slice)
            if isinstance(literal_key, str):
                key = literal_key
        literal = _constant(value)
        if _is_secret_key(key) and isinstance(literal, str) and not _placeholder(literal):
            self.add("AI010", node, "medium")
        if key == "NODE_TLS_REJECT_UNAUTHORIZED" and literal in ("0", 0):
            self.add("AI006", node, "high")
        if key == "DANGEROUSLY_OMIT_AUTH" and str(literal).lower() in {"true", "1"}:
            self.add("AI041", node, "high")
        if _norm(key) in {"verify", "verifyssl", "rejectunauthorized"} and literal is False:
            self.add("AI006", node)
        if _norm(key) in {"debug", "flaskdebug"} and literal is True:
            self.add("AI009", node)
        if re.search(r"token|nonce|password|secret", key, re.I):
            for child in ast.walk(value):
                if isinstance(child, ast.Call) and self.name(child.func).startswith("random."):
                    self.add("AI038", node)
                    break

    def visit_Assign(self, node):
        for target in node.targets:
            self._assignment(target, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._assignment(node.target, node.value, node)
        self.generic_visit(node)

    def visit_Dict(self, node):
        values = {_constant(key): value for key, value in zip(node.keys, node.values)
                  if isinstance(key, ast.Constant) and isinstance(key.value, str)}
        for key, value_node in values.items():
            literal = _constant(value_node)
            if _is_secret_key(key) and isinstance(literal, str) and not _placeholder(literal):
                self.add("AI010", value_node)
            norm = _norm(key)
            if norm in _AUTH_DISABLED and literal is False:
                self.add("AI026", value_node)
            if norm in _WILDCARD_PERMISSION_KEYS and _has_star(literal):
                self.add("AI027", value_node)
            if norm in _PASSTHROUGH_KEYS and literal is True:
                self.add("AI028", value_node)
            if norm == "autoapprove" and _unrestricted_approval(literal):
                self.add("AI031", value_node, "high")
        if _constant(values.get("role")) in {"system", "developer"} and self.external(values.get("content")):
            self.add("AI032", values["content"])
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.name(node.func)
        tail = name.rsplit(".", 1)[-1]
        keywords = {item.arg: item.value for item in node.keywords if item.arg is not None}
        first = node.args[0] if node.args else keywords.get("args", keywords.get("command"))
        value = lambda key: _constant(keywords.get(key))
        dynamic = first is not None and not _is_literal(first)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and dynamic:
            self.add("AI001", node)
        if name.startswith("subprocess.") and tail in {"run", "Popen", "call", "check_call", "check_output"} and value("shell") is True and dynamic:
            self.add("AI002", node, "high" if self.external(first) else "medium")
        if name == "asyncio.create_subprocess_shell" and dynamic:
            self.add("AI002", node, "high" if self.external(first) else "medium")
        if name.startswith("subprocess.") and isinstance(first, (ast.List, ast.Tuple)) and len(first.elts) >= 3:
            executable = _constant(first.elts[0])
            option = _constant(first.elts[1])
            if isinstance(executable, str) and PurePosixPath(executable).name in {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"} and option in {"-c", "-lc", "/c", "-Command"} and not _is_literal(first.elts[2]):
                self.add("AI002", node)
        if name in {"os.system", "os.popen"} and dynamic:
            self.add("AI003", node)
        if name in {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all", "ruamel.yaml.load"}:
            loader = keywords.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            if self.name(loader).rsplit(".", 1)[-1] not in {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}:
                self.add("AI004", node, "high" if "unsafe" in name else "medium")
        if name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads", "joblib.load"}:
            self.add("AI005", node)
        if ((value("verify") is False and any(part in name.lower() for part in ("request", "httpx", "client", "session", ".get", ".post", ".put", ".delete")))
                or value("cert_reqs") == 0 or (name == "aiohttp.TCPConnector" and value("ssl") is False)
                or name == "ssl._create_unverified_context"):
            self.add("AI006", node, "high")
        if any(_has_star(value(key)) for key in ("allow_origins", "origins", "origin")) or (tail == "CORS" and _has_star(value("resources"))):
            self.add("AI007", node, "high")
        if value("host") in {"0.0.0.0", "::", "[::]"}:
            self.add("AI008", node, "high")
        if value("debug") is True:
            self.add("AI009", node, "high")
        if name == "tempfile.mktemp":
            self.add("AI016", node, "high")
        if "jwt" in name.lower() and tail == "decode":
            options = value("options")
            algorithms = value("algorithms")
            has_none = isinstance(algorithms, (list, tuple, str)) and "none" in algorithms
            if (isinstance(options, dict) and options.get("verify_signature") is False) or value("verify") is False or has_none:
                self.add("AI017", node, "high")
        request_function = name.startswith(("requests.", "httpx.", "urllib.request.")) and tail in {"get", "post", "put", "patch", "delete", "head", "options", "request", "urlopen", "Request"}
        request_function = request_function or name in {"aiohttp.ClientSession.get", "aiohttp.ClientSession.post"}
        receiver = node.func.value.id if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) else None
        receiver_type = self.object_types.get(receiver)
        if receiver_type in {"requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession"} and tail in {"get", "post", "put", "patch", "delete", "head", "options", "request"}:
            request_function = True
        url = keywords.get("url") or (node.args[1] if tail == "request" and len(node.args) > 1 else first)
        if request_function and self.external(url):
            self.add("AI014", node)
        if (name in {"open", "io.open", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "shutil.copy", "shutil.copyfile"} and self.external(first)):
            self.add("AI015", node)
        if name in {"pathlib.Path", "Path"} and self.external(first):
            # Path construction alone is not an I/O sink; the enclosing call is checked below.
            pass
        if tail in {"read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir"} and isinstance(node.func, ast.Attribute) and self.external(node.func.value):
            self.add("AI015", node)
        if name == "torch.load" and value("weights_only") is False:
            self.add("AI035", node, "high")
        if name.endswith("load_model") and value("safe_mode") is False:
            self.add("AI035", node, "high")
        if tail in {"execute", "executemany", "executescript"} and first is not None and _interpolated(first):
            self.add("AI036", node)
        if tail in {"extract", "extractall"} and (receiver_type == "tarfile.open" or receiver in {"tar", "tarfile", "tar_archive"}):
            if value("filter") != "data":
                self.add("AI037", node, "medium" if receiver_type == "tarfile.open" else "low")
        if name in {"flask.render_template_string", "render_template_string", "jinja2.Template"} and dynamic:
            self.add("AI039", node)
        if any(part in name.lower() for part in ("logging.", "logger.", "log.")) and tail in {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}:
            if any(isinstance(child, ast.Name) and _is_secret_key(child.id) or isinstance(child, ast.Attribute) and _is_secret_key(child.attr)
                   or isinstance(child, ast.Subscript) and isinstance(_constant(child.slice), str) and _is_secret_key(_constant(child.slice))
                   for arg in node.args for child in ast.walk(arg)):
                self.add("AI033", node)
        for key, val_node in keywords.items():
            literal = _constant(val_node)
            if _is_secret_key(key) and isinstance(literal, str) and not _placeholder(literal):
                self.add("AI010", val_node)
            if _norm(key) in _AUTH_DISABLED and literal is False:
                self.add("AI026", val_node)
            if _norm(key) in _WILDCARD_PERMISSION_KEYS and _has_star(literal):
                self.add("AI027", val_node)
            if _norm(key) in _PASSTHROUGH_KEYS and literal is True:
                self.add("AI028", val_node)
            if _norm(key) == "autoapprove" and _unrestricted_approval(literal):
                self.add("AI031", val_node, "high")
        self.generic_visit(node)


def _json_analysis(findings, text, path):
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return
    positions = {}
    for match in re.finditer(r'"((?:[^"\\]|\\.)*)"\s*:', text):
        try:
            key = json.loads('"' + match.group(1) + '"')
        except ValueError:
            continue
        positions.setdefault(key, []).append(match.start())
    cursors = {}
    mcp_file = "mcp" in path.lower() or (isinstance(data, dict) and any(_norm(key) in {"mcpservers", "mcp"} for key in data))

    def add(rule, offset, confidence="medium", detail=None):
        findings.offset(rule, offset, confidence=confidence, detail=detail)

    def walk(value, context=False, parents=()):
        if isinstance(value, list):
            for item in value:
                walk(item, context, parents)
        if not isinstance(value, dict):
            return
        is_mcp = context or any(_norm(key) == "mcpservers" for key in value) or (mcp_file and "command" in value)
        for key, item in value.items():
            occurrences = positions.get(key, [0])
            ordinal = cursors.get(key, 0)
            offset = occurrences[min(ordinal, len(occurrences) - 1)]
            cursors[key] = ordinal + 1
            norm = _norm(key)
            if _is_secret_key(key) and isinstance(item, str) and not _placeholder(item):
                add("AI010", offset)
            if norm in _AUTH_DISABLED and item is False:
                add("AI026", offset)
            if norm in _WILDCARD_PERMISSION_KEYS and _has_star(item):
                add("AI027", offset)
            if norm in _PASSTHROUGH_KEYS and item is True:
                add("AI028", offset)
            if norm in {"verify", "verifyssl", "rejectunauthorized", "tlsverify"} and item is False:
                add("AI006", offset, "high")
            if key == "NODE_TLS_REJECT_UNAUTHORIZED" and str(item) == "0":
                add("AI006", offset, "high")
            if key == "DANGEROUSLY_OMIT_AUTH" and str(item).lower() in {"true", "1"}:
                add("AI041", offset, "high")
            if norm in {"alloworigins", "origins", "corsorigins"} and _has_star(item):
                add("AI007", offset, "high")
            if norm == "host" and item in ("0.0.0.0", "::", "[::]"):
                add("AI008", offset, "high")
            if norm == "debug" and item is True:
                add("AI009", offset, "high")
            if norm == "dangerouslyallowbrowser" and item is True:
                add("AI030", offset, "high")
            if norm in {"dangerouslyskippermissions", "bypasspermissions", "yolo", "autoapproveall"} and item is True:
                add("AI031", offset, "high")
            if norm == "autoapprove" and _unrestricted_approval(item):
                add("AI031", offset, "high")
            if norm in {"approvalpolicy", "permissionmode", "sandboxmode"} and item in ("never", "bypassPermissions", "danger-full-access"):
                add("AI031", offset, "high")
            if (is_mcp or mcp_file or "mcp" in parents) and norm in {"url", "endpoint", "serverurl"} and _remote_http(item):
                add("AI029", offset, "high")
            if norm == "command" and is_mcp and isinstance(item, str):
                args = value.get("args", [])
                if isinstance(args, list) and PurePosixPath(item).name in {"npx", "uvx", "bunx", "pnpx"}:
                    package = None
                    skip_next = False
                    for arg in args:
                        if not isinstance(arg, str):
                            continue
                        if skip_next:
                            skip_next = False
                            continue
                        if arg in {"--from", "--package", "-p"}:
                            # The next token selects the runnable distribution.
                            next_index = args.index(arg) + 1
                            if next_index < len(args):
                                package = args[next_index]
                            break
                        if arg in {"--index-url", "--registry", "--python"}:
                            skip_next = True
                            continue
                        if not arg.startswith("-"):
                            package = arg
                            break
                    if package is not None and _unpinned_package(package):
                        add("AI018", offset, "high")
            if PurePosixPath(path).name == "package.json" and key in {"dependencies", "devDependencies", "optionalDependencies"} and isinstance(item, dict):
                for package, version in item.items():
                    if isinstance(version, str) and not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", version) and not version.startswith(("file:", "workspace:", "link:")):
                        dep_offsets = positions.get(package, [offset])
                        add("AI025", dep_offsets[0], "low", "Dependency: " + package + ". A lockfile may pin its resolved version.")
            walk(item, is_mcp or norm in {"mcp", "mcpservers"}, parents + (key,))

    walk(data, mcp_file)


def _regex(findings, text, rule, pattern, flags=0, confidence="medium", predicate=None):
    for match in re.finditer(pattern, text, flags):
        line_start = text.rfind("\n", 0, match.start()) + 1
        prefix = text[line_start:match.start()].lstrip()
        if prefix.startswith(("#", "//", "*", "<!--")):
            continue
        if predicate is None or predicate(match):
            findings.offset(rule, match.start(), match.end(), confidence)


def _js_analysis(findings, text):
    clean = _strip_comments(text)
    # Build bounded aliases only from actual child_process imports/requires.
    exec_aliases = set()
    namespaces = set()
    for match in re.finditer(r"(?:import\s*\{([^}]{1,500})\}\s*from\s*|(?:const|let|var)\s*\{([^}]{1,500})\}\s*=\s*require\s*\()\s*['\"](?:node:)?child_process['\"]", clean):
        for item in (match.group(1) or match.group(2)).split(","):
            names = re.split(r"\s+as\s+|\s*:\s*", item.strip())
            if names[0] in {"exec", "execSync"}:
                exec_aliases.add(names[-1])
    for match in re.finditer(r"(?:import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\()\s*['\"](?:node:)?child_process['\"]", clean):
        namespaces.add(match.group(1) or match.group(2))
    call_names = [re.escape(item) for item in exec_aliases]
    call_names += [re.escape(item) + r"\.(?:exec|execSync)" for item in namespaces]
    if call_names:
        names = "(?:" + "|".join(call_names) + ")"
        _regex(findings, clean, "AI012", r"\b" + names + r"\s*\(\s*(?!(?:['\"][^'\"\n]{0,1000}['\"]\s*[,)]|`[^`$]{0,1000}`\s*[,)]))[^\n;]{1,1000}")
    _regex(findings, clean, "AI013", r"\b(?:eval|new\s+Function)\s*\(\s*(?!['\"])[A-Za-z_$`][^;\n]{0,1000}")
    _regex(findings, clean, "AI006", r"\brejectUnauthorized\s*:\s*false\b", confidence="high")
    _regex(findings, clean, "AI006", r"\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*\]?\s*=\s*['\"]0['\"]", confidence="high")
    _regex(findings, clean, "AI007", r"\b(?:origin|origins|allowOrigins)\s*:\s*(?:\[\s*)?['\"]\*['\"]", confidence="high")
    _regex(findings, clean, "AI008", r"\b(?:listen|host)\s*(?:\([^\n]{0,80},|:)\s*['\"](?:0\.0\.0\.0|::)['\"]", confidence="high")
    _regex(findings, clean, "AI017", r"\balgorithms\s*:\s*\[\s*['\"]none['\"]", confidence="high")
    _regex(findings, clean, "AI026", r"\b(?:auth|authentication|requireAuth|authEnabled)\s*:\s*false\b")
    _regex(findings, clean, "AI028", r"\b(?:tokenPassthrough|allowTokenPassthrough|forwardAccessToken|forwardAuthorization)\s*:\s*true\b", confidence="high")
    _regex(findings, clean, "AI030", r"\bdangerouslyAllowBrowser\s*:\s*true\b", confidence="high")
    _regex(findings, clean, "AI031", r"\b(?:dangerouslySkipPermissions|bypassPermissions|autoApproveAll)\s*:\s*true\b", confidence="high")
    _regex(findings, clean, "AI031", r"\b(?:autoApprove|auto_approve)\s*:\s*(?:true\b|\[(?=[^\]]{0,1000}['\"]\*['\"])[^\]]{0,1000}\])", confidence="high")
    _regex(findings, clean, "AI027", r"\b(?:allowedTools|toolAllowlist|permissions|allowedResources)\s*:\s*(?:\[\s*)?['\"]\*['\"]", confidence="high")
    external = r"(?:req(?:uest)?\.(?:body|query|params)|user(?:Input|Url|Path|_input|_url|_path)|tool(?:Input|Output|Result|_input|_output|_result))"
    _regex(findings, clean, "AI014", r"\b(?:fetch|axios\.(?:get|post|request))\s*\(\s*" + external + r"[^;\n]{0,500}")
    _regex(findings, clean, "AI015", r"\b(?:fs(?:\.promises)?\.)?(?:readFile|readFileSync|writeFile|writeFileSync|unlink|rm)\s*\(\s*" + external + r"[^;\n]{0,500}")
    _regex(findings, clean, "AI032", r"\brole\s*:\s*['\"](?:system|developer)['\"]\s*,\s*content\s*:\s*(?:`[^`]{0,500})?" + external + r"[^;\n]{0,500}")
    _regex(findings, clean, "AI033", r"\b(?:console|logger|log)\.(?:log|info|warn|error|debug)\s*\([^\n;]{0,500}\b(?:apiKey|api_key|accessToken|access_token|clientSecret|client_secret|password)\b[^\n;]{0,200}")
    _regex(findings, clean, "AI036", r"\.(?:query|execute)\s*\(\s*`[^`]{0,1000}\$\{[^`]{0,500}`")
    _regex(findings, clean, "AI040", r"\b(?:innerHTML|outerHTML)\s*=\s*(?!['\"])[A-Za-z_$`][^;\n]{0,500}")
    _regex(findings, clean, "AI040", r"\bdangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!['\"])[^}\n]{1,500}")
    _regex(findings, clean, "AI040", r"\binsertAdjacentHTML\s*\(\s*['\"][^'\"]{1,30}['\"]\s*,\s*(?!['\"])[^;\n]{1,500}")


def _generic_analysis(findings, text, path, suffix):
    clean = _strip_comments(text) if suffix in _JS_SUFFIXES or suffix == ".jsonc" else text
    _regex(findings, clean, "AI011", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", confidence="high")
    _regex(findings, clean, "AI034", r"https?://[^\s'\"<>]{1,1500}[?&](?:access_token|api_key|apikey|client_secret|token)=(?P<secret>[^\s'\"&<>]{8,500})", re.I,
           predicate=lambda match: not _placeholder(match.group("secret")))
    # Generic secrets cover dotenv, YAML, JS and shell; Python/JSON have syntax-aware checks.
    if suffix not in {".py", ".pyi", ".json", ".jsonc"}:
        secret_pattern = r"\b(?P<key>[A-Za-z_][A-Za-z0-9_-]{0,80})\s*[:=]\s*(?P<quote>['\"])(?P<secret>[^'\"\r\n]{8,500})(?P=quote)"
        _regex(findings, clean, "AI010", secret_pattern,
               predicate=lambda match: _is_secret_key(match.group("key")) and not _placeholder(match.group("secret")))
        if suffix in {".env", ".yaml", ".yml", ".ini", ".cfg", ".toml"} or PurePosixPath(path).name.startswith(".env"):
            _regex(findings, clean, "AI010", r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_-]{0,80})\s*[:=]\s*(?P<secret>[^\s'\"#][^\s#]{7,499})\s*(?:#.*)?$", re.M,
                   predicate=lambda match: _is_secret_key(match.group("key")) and not _placeholder(match.group("secret")))
    # Standalone recognizable key formats supplement semantic key names.
    _regex(findings, clean, "AI010", r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,255}|sk-(?:proj-)?[A-Za-z0-9_-]{24,255})\b")
    _regex(findings, clean, "AI010", r"\b(?:Authorization|authorization)['\"]?\s*[:=]\s*['\"]Bearer\s+(?P<secret>[A-Za-z0-9._~+/-]{12,500})['\"]",
           predicate=lambda match: not _placeholder(match.group("secret")))
    if suffix in _CONFIG_SUFFIXES or suffix in {".sh", ".bash", ".zsh", ".ps1"} or "dockerfile" in PurePosixPath(path).name.lower():
        _regex(findings, clean, "AI019", r"\b(?:curl|wget)\b[^\n|]{1,1000}\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b", confidence="high")
        _regex(findings, clean, "AI031", r"--(?:dangerously-skip-permissions|dangerously-bypass-approvals-and-sandbox|yolo)\b", confidence="high")
        _regex(findings, clean, "AI041", r"\bDANGEROUSLY_OMIT_AUTH\b['\"]?\s*[:=]\s*['\"]?(?:true|1)\b", re.I, "high")
    if suffix in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"}:
        _regex(findings, clean, "AI031", r"^\s*(?:autoApprove|auto_approve)\s*[:=]\s*(?:true\b|\[(?=[^\]\n]{0,1000}['\"]\*['\"])[^\]\n]{0,1000}\])", re.M, "high")
        if suffix in {".yaml", ".yml"}:
            _regex(findings, clean, "AI031", r"^(?P<indent>[ \t]*)(?:autoApprove|auto_approve)\s*:\s*\n(?P<items>(?:(?P=indent)[ \t]*-[^\n]*(?:\n|$)){1,50})", re.M, "high",
                   lambda match: bool(re.search(r"^\s*-\s*['\"]\*['\"]\s*(?:#.*)?$", match.group("items"), re.M)))
        _regex(findings, clean, "AI006", r"^\s*(?:verify|verify_ssl|tls_verify|rejectUnauthorized)\s*[:=]\s*false\b", re.M | re.I, "high")
        _regex(findings, clean, "AI026", r"^\s*(?:auth|authentication|require_auth|auth_enabled)\s*[:=]\s*false\b", re.M | re.I)
        _regex(findings, clean, "AI028", r"^\s*(?:token_passthrough|allow_token_passthrough|forward_authorization)\s*[:=]\s*true\b", re.M | re.I, "high")
        _regex(findings, clean, "AI027", r"^\s*(?:allowed_tools|permissions|allowed_resources)\s*[:=]\s*(?:\[\s*)?['\"]\*['\"]", re.M, "high")
        _regex(findings, clean, "AI009", r"^\s*(?:debug|FLASK_DEBUG)\s*[:=]\s*(?:true|1)\b", re.M | re.I, "high")
        _regex(findings, clean, "AI008", r"^\s*host\s*[:=]\s*['\"]?(?:0\.0\.0\.0|::)(?:['\"]|\s|$)", re.M, "high")
        _regex(findings, clean, "AI022", r"^\s*(?:privileged|allowPrivilegeEscalation)\s*:\s*true\b", re.M, "high")
        _regex(findings, clean, "AI023", r"(?:/var/run/docker\.sock|/run/(?:docker|containerd/containerd)\.sock)", confidence="high")
        _regex(findings, clean, "AI042", r"^\s*(?:(?:network_mode|pid)\s*:\s*['\"]?host\b|(?:hostPID|hostNetwork)\s*:\s*true\b)", re.M, "high")
        _regex(findings, clean, "AI024", r"^\s*image\s*:\s*['\"]?(?P<image>[^\s'\"#]+)", re.M, "low",
               lambda match: "@sha256:" not in match.group("image") and "${" not in match.group("image"))
        if "/.github/workflows/" in "/" + path.replace("\\", "/"):
            _regex(findings, clean, "AI020", r"^\s*-?\s*uses\s*:\s*['\"]?(?P<action>[^\s'\"#]+)", re.M, "high",
                   lambda match: not match.group("action").startswith(("./", "docker://")) and not re.search(r"@[a-fA-F0-9]{40}$", match.group("action")))
    if "dockerfile" in PurePosixPath(path).name.lower():
        _regex(findings, clean, "AI021", r"^\s*USER\s+(?:root|0)(?::\S+)?\s*(?:#.*)?$", re.M | re.I, "high")
        stage_names = set()
        for match in re.finditer(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?", clean, re.M | re.I):
            image = match.group("image")
            if image.lower() != "scratch" and image not in stage_names and "@sha256:" not in image and "$" not in image:
                findings.offset("AI024", match.start(), match.end(), "low")
            if match.group("stage"):
                stage_names.add(match.group("stage"))
    name = PurePosixPath(path).name.lower()
    if (name.startswith("requirements") and suffix == ".txt") or name == "requirements.in":
        for index, line in enumerate(text.splitlines(), 1):
            content = line.strip()
            if not content or content.startswith(("#", "-", "\\")):
                continue
            requirement = content.split(";", 1)[0].split(" #", 1)[0].strip().rstrip("\\").strip()
            if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[^]]+\])?\s*==\s*[^*\s,]+(?:\s+--hash=\S+)*$", requirement):
                findings.add("AI025", index, confidence="low")


def analyze_file_errors(path: str, text: str) -> list[str]:
    """Return parse/coverage errors separately from vulnerabilities."""
    suffix = PurePosixPath(path).suffix.lower()
    try:
        if suffix in {".py", ".pyi"}:
            ast.parse(text, filename=path)
        elif suffix in {".json", ".jsonc"}:
            json.loads(_strip_comments(text) if suffix == ".jsonc" else text)
    except SyntaxError as error:
        return ["Python syntax could not be parsed at line %s: %s; AST-based checks were skipped." % (error.lineno or 1, error.msg)]
    except json.JSONDecodeError as error:
        return ["JSON could not be parsed at line %s: %s; structured configuration checks were skipped." % (error.lineno, error.msg)]
    except (ValueError, RecursionError, MemoryError) as error:
        return ["Source could not be parsed (%s); syntax-aware checks were skipped." % type(error).__name__]
    return []


def analyze_file(path: str, text: str) -> list[dict]:
    """Analyze one text file without reading imports, making requests, or executing it."""
    findings = _Findings(path, text)
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".py", ".pyi"}:
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            # The caller obtains these coverage gaps from analyze_file_errors.
            pass
        else:
            try:
                _PythonAnalyzer(findings).visit(tree)
            except MemoryError as error:
                # Parsing success does not imply visitor success. Surface visitor
                # resource failures to the caller instead of reporting a clean file.
                raise ValueError("Python AST analysis exceeded available memory") from error
    if suffix in _JS_SUFFIXES:
        _js_analysis(findings, text)
    if suffix in {".json", ".jsonc"}:
        _json_analysis(findings, _strip_comments(text) if suffix == ".jsonc" else text, path)
    _generic_analysis(findings, text, path, suffix)
    return sorted(findings.items, key=lambda item: (item["line"], item["rule_id"]))
