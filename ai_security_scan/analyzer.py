"""Offline, deterministic source analysis. Never imports or executes target code.

Python rules use the syntax tree and simple local source tracking. JS/TS and YAML
rules are deliberately bounded lexical checks. JSON config rules traverse parsed
objects. Findings identify reviewable evidence, not whole-program vulnerability
proofs. Unsupported dynamic configuration needs manual review.
"""
from __future__ import annotations

import ast
import ipaddress
import json
import math
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
    if lowered in {"your_api_key", "your-api-key", "redacted", "placeholder", "example-token", "example-key", "test-token", "test-secret", "dummy-secret", "your-token-here", "sk-your-key-here", "api-key-not-set", "codex-subscription-auth"}:
        return True
    if re.fullmatch(r"(?:x+|\*+|\.+|0+)", value, re.I):
        return True
    if lowered.startswith(("replace_me", "replace-me", "your_api_key_here", "your-api-key-here", "example_", "dummy_")):
        return True
    return False


def _credential_literal(key, value):
    if not _is_secret_key(key) or not isinstance(value, str) or _placeholder(value):
        return False
    # Both the identifier role and a narrow authentication error message must
    # agree. Never suppress a secret-shaped value merely because its name says
    # "error", or suppress an actual password field containing a human phrase.
    error_role = re.search(r"(?:^|[_-])(?:error|message)$", key, re.I)
    error_message = re.fullmatch(
        r"(?:invalid|missing|expired|incorrect|unauthorized) (?:api key|access token|auth token|password|credentials)[.!]?",
        value.strip(), re.I)
    return not (error_role and error_message)


def _private_key_body(text, marker_end):
    # A PEM marker in an example or a parser's marker constant is not private
    # key material. Require a plausible encoded body, including truncated keys.
    # This deliberately does not claim cryptographic validity or key usage.
    tail = text[marker_end:marker_end + 32768].replace("\\r\\n", "\n").replace("\\n", "\n")
    return bool(re.match(
        r"\s*(?:(?:Proc-Type|DEK-Info):[^\n]*\n\s*)*[A-Za-z0-9+/]{32,}={0,2}(?=\s|-----END|['\"]|$)",
        tail))


def _docker_final_root(findings, text):
    """Track explicit USER state for the default final Docker stage only.

    Ignore continued instruction bodies and heredoc contents. External image
    defaults, variables and non-default --target builds remain unproven.
    """
    stages, stage, root = {}, None, None
    escape, pending, start, heredocs, seen_instruction = "\\", "", 0, [], False
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = line.rstrip("\r\n")
            if (candidate.lstrip("\t") if strip_tabs else candidate) == delimiter:
                heredocs.pop(0)
            offset += len(line)
            continue
        if stripped.startswith("#"):
            directive = re.fullmatch(r"#\s*escape\s*=\s*([\\`])", stripped, re.I)
            if directive and not pending and not seen_instruction:
                escape = directive.group(1)
            offset += len(line)
            continue
        if pending and not stripped:
            offset += len(line)
            continue
        if not pending:
            start = offset
        content = line.rstrip("\r\n")
        continued = content.rstrip().endswith(escape)
        pending += content.rstrip()[:-1] + " " if continued else content
        offset += len(line)
        if continued:
            continue
        instruction, pending = pending, ""
        match = re.match(r"^\s*(?P<op>[A-Za-z]+)\s+(?P<args>.*)$", instruction)
        if not match:
            continue
        seen_instruction = True
        op, args = match.group("op").upper(), match.group("args").strip()
        if op in {"RUN", "COPY", "ADD"}:
            heredocs = [(next(value for value in groups[1:] if value), bool(groups[0])) for groups in re.findall(
                r"(?<!<)<<(-?)\s*(?:'([^'\r\n]+)'|\"([^\"\r\n]+)\"|([^\s;|&<>'\"]+))", args)]
        if op == "FROM":
            if stage is not None:
                stages[stage] = root
            source = re.match(r"(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?", args, re.I)
            if source:
                root = stages.get(source.group("image").lower())
                stage = source.group("stage").lower() if source.group("stage") else None
            else:
                stage, root = None, None
        elif op == "USER":
            # Inline '#' is not a Docker comment; invalid or dynamically
            # resolved users cannot establish a literal final root identity.
            root = (start, offset) if re.fullmatch(r"(?:root|0+)(?::[^\s]+)?", args) else None
    if root:
        findings.offset("AI021", root[0], root[1], "high")


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


def _inspector_nonempty(value):
    # Inspector tests the environment string's presence, not Boolean syntax:
    # both "false" and "0" disable authentication. Python os.environ and MCP
    # JSON env maps require strings; invalid scalar/container values are not
    # evidence that a nonempty environment string reaches Inspector.
    return isinstance(value, str) and bool(value)


def _inspector_env_assignments(findings, text, path, suffix):
    """Recognize literal assignments without matching quoted help/reference text.

    Structured JSON, Python and JS have their own paths. Expansion-dependent
    shell/config values remain unproven, even if their variable name is risky.
    """
    config = suffix in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"} or PurePosixPath(path).name.startswith(".env")
    shell = suffix in {".sh", ".bash", ".zsh", ".ps1"} or "dockerfile" in PurePosixPath(path).name.lower()
    if not (config or shell):
        return
    literal = r"(?P<literal>'[^'\r\n]*'|\"(?:[^\"\\\r\n]|\\[^\r\n])*\"|[^\s#;'\"`]+)"
    assignment = re.compile(r"(?P<key>['\"]?DANGEROUSLY_OMIT_AUTH['\"]?)[ \t]*(?P<separator>[:=])[ \t]*" + literal)
    earlier_assignment = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=" + literal)
    offset, yaml_block_indent = 0, None
    for line in text.splitlines(keepends=True):
        if suffix in {".yaml", ".yml"}:
            indent = len(line) - len(line.lstrip(" \t"))
            if yaml_block_indent is not None:
                if not line.strip() or indent > yaml_block_indent:
                    offset += len(line)
                    continue
                yaml_block_indent = None
            if re.search(r":\s*[|>](?:[+-]?[1-9]?|[1-9][+-]?)\s*(?:#.*)?$", line):
                # Contents of folded/literal scalars are data, not keys.
                # Resolving an env value encoded this way is outside this
                # lexical check; do not invent assignments from help text.
                yaml_block_indent = indent
                offset += len(line)
                continue
        # Only assignment contexts: dotenv/config keys, shell export/env or a
        # command-prefix assignment, and Docker ENV/RUN. No arbitrary search
        # inside descriptions, echo arguments, comments, or labels.
        prefix = re.match(r"[ \t]*(?:-[ \t]+)?", line).end()
        if shell:
            command = re.match(r"(?:(?:/bin/(?:sh|bash) -c[ \t]+)?(?:#\(nop\)[ \t]+)?)(?:RUN[ \t]+)?(?:(?:ENV|export|env)[ \t]+)?(?:\$env:)?", line[prefix:])
            prefix += command.end()
            # Legacy Docker ENV NAME value uses a space rather than '='.
            legacy = re.match(r"[ \t]*ENV[ \t]+DANGEROUSLY_OMIT_AUTH[ \t]+" + literal, line)
        else:
            legacy = None
            export = re.match(r"export[ \t]+", line[prefix:])
            if export:
                prefix += export.end()
        match = legacy or assignment.match(line, prefix)
        if shell and not match:
            # ENV A=literal B=literal and shell command-prefix assignments.
            # Stop at the command name, so echo/reference strings stay inert.
            previous = earlier_assignment.match(line, prefix)
            while previous:
                prefix = previous.end()
                prefix += len(line[prefix:]) - len(line[prefix:].lstrip(" \t"))
                match = assignment.match(line, prefix)
                if match:
                    break
                previous = earlier_assignment.match(line, prefix)
        if match:
            raw = match.group("literal")
            quoted = raw.startswith(("'", '"'))
            value = raw[1:-1] if quoted else raw
            dynamic = (not raw.startswith("'") and bool(re.search(r"(?<!\\)[$`]", value)))
            # YAML null/container values do not establish an environment
            # string. Other supported lexical formats retain literal text.
            typed_scalar = suffix == ".toml" or suffix in {".yaml", ".yml"} and match.group("separator") == ":"
            nonstring = not quoted and typed_scalar and (value.lower() in {"null", "~", "true", "false"} or value.startswith(("[", "{", "|", ">", "&", "*", "!")) or bool(re.fullmatch(r"[-+]?(?:[0-9][0-9_.eE+-]*|0[xob][0-9a-fA-F_]+|\.(?:inf|nan))", value, re.I)))
            if value and not dynamic and not nonstring:
                findings.offset("AI041", offset + match.start(), offset + match.end(), "high")
        offset += len(line)


def _unpinned_package(value):
    if not isinstance(value, str) or value.startswith(("-", ".", "/", "file:", "workspace:")):
        return False
    if "==" in value:
        return not bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_.,-]+\])?\s*==\s*[0-9][A-Za-z0-9.!+_-]*", value))
    if "@" in value[1:]:
        version = value.rsplit("@", 1)[1]
        return not _exact_npm_version(version)
    return True


def _exact_npm_version(value):
    return bool(re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?(?:\+[a-zA-Z0-9.-]+)?", value))


def _remote_http(value):
    if not isinstance(value, str):
        return False
    # Normalize the leading C0/space characters accepted by URL parsers.
    value = value.lstrip("".join(chr(code) for code in range(33)))
    if not value.lower().startswith("http://"):
        return False
    try:
        host = urlsplit(value).hostname or ""
    except ValueError:
        return True
    if host.lower() == "localhost":
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    return not (mapped or address).is_loopback


def _runner_packages(command, args):
    """Select literal distribution specs, not the binary or its arguments.

    Handles common npx/uvx forms; this does not resolve wrapper scripts, shell
    expressions, environment variables, lockfiles or transitive dependencies.
    """
    runner = PurePosixPath(command.replace("\\", "/")).name.lower()
    if runner.endswith((".cmd", ".exe")):
        runner = runner[:-4]
    if runner == "uv" and args[:2] == ["tool", "run"]:
        runner, args = "uvx", args[2:]
    if runner not in {"npx", "uvx", "bunx", "pnpx"}:
        return []
    selected, additional, positional = [], [], None
    selectors = {"--from"} if runner == "uvx" else {"--package", "-p"}
    extras = {"--with"} if runner == "uvx" else set()
    value_options = {"--index-url", "--extra-index-url", "--registry", "--python",
                     "--index", "--default-index", "--directory", "--project",
                     "--cache-dir", "--config-file", "--constraint", "--override"}
    index = 0
    while index < len(args):
        arg = args[index]
        if not isinstance(arg, str):
            index += 1
            continue
        key, equal, attached = arg.partition("=")
        if key in selectors | extras:
            if equal:
                spec = attached
            elif index + 1 < len(args) and isinstance(args[index + 1], str):
                index += 1
                spec = args[index]
            else:
                spec = None
            if spec:
                (selected if key in selectors else additional).append(spec)
        elif runner in {"npx", "pnpx"} and arg.startswith("-p") and not arg.startswith("--") and len(arg) > 2:
            selected.append(arg[2:])
        elif key in value_options and not equal:
            index += 1
        elif key in {"-c", "--call"}:
            break
        elif arg == "--":
            positional = args[index + 1] if index + 1 < len(args) else None
            break
        elif not arg.startswith("-"):
            positional = arg
            break
        index += 1
    return selected + additional + ([positional] if not selected and isinstance(positional, str) else [])


def _load_source_json(text):
    """Reject ambiguous/nonstandard JSON rather than silently losing fields."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON object key; structured configuration checks were skipped")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("Non-finite JSON number; structured configuration checks were skipped")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            return nonfinite(value)
        return number

    return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)


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
    _MAX_WORK = 1000000
    _MAX_ALTERNATIVES = 64

    def __init__(self, findings):
        self.findings = findings
        self.aliases = {}
        self.external_scopes = [{}]
        self.object_types = {}
        self.static_values = set()
        self.literal_values = {}
        self.interpolated_values = set()
        self.class_outer_state = None
        self.work = 0

    def _charge(self, amount=1):
        self.work += amount
        if self.work > self._MAX_WORK:
            raise ValueError("Python local analysis exceeded its deterministic work budget; coverage is incomplete")

    def visit(self, node):
        self._charge()
        return super().visit(node)

    def names(self, node):
        """Possible local aliases; joins retain alternatives rather than erase them."""
        if isinstance(node, ast.Name):
            value = self.aliases.get(node.id, node.id)
            return value if isinstance(value, frozenset) else frozenset([value])
        if isinstance(node, ast.Attribute):
            return frozenset(name + "." + node.attr for name in (self.names(node.value) or [""]))
        return frozenset()

    def name(self, node):
        names = self.names(node)
        return next(iter(names)) if len(names) == 1 else ""

    def literal(self, node):
        if isinstance(node, ast.Name):
            values = self.literal_values.get(node.id, [])
            return values[0] if len(values) == 1 else None
        return _constant(node)

    def literals(self, node):
        if isinstance(node, ast.Name):
            return self.literal_values.get(node.id, [])
        value = _constant(node)
        return [value] if value is not None or isinstance(node, ast.Constant) else []

    def static(self, node, depth=0):
        """Bounded syntactic constant proof: no target expressions are evaluated."""
        self._charge()
        if node is None or depth > 32:
            return False
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.static_values
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self.static(item, depth + 1) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(self.static(key, depth + 1) and self.static(value, depth + 1)
                       for key, value in zip(node.keys, node.values))
        if isinstance(node, ast.JoinedStr):
            return all(self.static(item, depth + 1) for item in node.values)
        if isinstance(node, ast.FormattedValue):
            return self.static(node.value, depth + 1) and (node.format_spec is None or self.static(node.format_spec, depth + 1))
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self.static(node.left, depth + 1) and self.static(node.right, depth + 1)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return (self.static(node.func.value, depth + 1)
                    and all(self.static(arg, depth + 1) for arg in node.args)
                    and all(item.arg is not None and self.static(item.value, depth + 1) for item in node.keywords))
        return False

    def interpolation(self, node):
        return ((isinstance(node, ast.Name) and node.id in self.interpolated_values)
                or (_interpolated(node) and not self.static(node)))

    def immutable_static(self, node):
        # Mutable containers can be changed through aliases or unknown calls;
        # never use their initial contents to prove a later Name is constant.
        if isinstance(node, (ast.List, ast.Dict, ast.Set)):
            return False
        if isinstance(node, ast.Tuple):
            return all(self.immutable_static(item) for item in node.elts)
        if isinstance(node, ast.BinOp):
            return self.immutable_static(node.left) and self.immutable_static(node.right)
        return self.static(node)

    def _state(self):
        self._charge(len(self.aliases) + sum(len(scope) for scope in self.external_scopes)
                     + len(self.object_types) + len(self.static_values)
                     + len(self.literal_values) + len(self.interpolated_values))
        return (self.aliases.copy(), [scope.copy() for scope in self.external_scopes],
                self.object_types.copy(), self.static_values.copy(),
                self.literal_values.copy(), self.interpolated_values.copy())

    def _restore(self, state):
        aliases, scopes, types, static, literals, interpolated = state
        self._charge(len(aliases) + sum(len(scope) for scope in scopes) + len(types)
                     + len(static) + len(literals) + len(interpolated))
        self.aliases, self.external_scopes = aliases.copy(), [scope.copy() for scope in scopes]
        self.object_types, self.static_values = types.copy(), static.copy()
        self.literal_values, self.interpolated_values = literals.copy(), interpolated.copy()

    def _join(self, states):
        self._restore(states[0])
        for other in states[1:]:
            aliases, scopes, types, static, literals, interpolated = other
            for key in set(self.aliases) | set(aliases):
                left, right = self.aliases.get(key, key), aliases.get(key, key)
                left = left if isinstance(left, frozenset) else frozenset([left])
                right = right if isinstance(right, frozenset) else frozenset([right])
                self.aliases[key] = left | right
                if len(self.aliases[key]) > self._MAX_ALTERNATIVES:
                    raise ValueError("Python local analysis exceeded its alias alternative limit; coverage is incomplete")
            for current, additional in zip(self.external_scopes, scopes):
                for key in set(current) | set(additional):
                    current[key] = current.get(key, key in _EXTERNAL_NAMES) or additional.get(key, key in _EXTERNAL_NAMES)
            self.object_types = {key: value for key, value in self.object_types.items() if types.get(key) == value}
            self.static_values.intersection_update(static)
            for key in set(self.literal_values) | set(literals):
                values = list(self.literal_values.get(key, []))
                for value in literals.get(key, []):
                    if not any(type(value) is type(previous) and value == previous for previous in values):
                        values.append(value)
                self.literal_values[key] = values
                if len(values) > self._MAX_ALTERNATIVES:
                    raise ValueError("Python local analysis exceeded its literal alternative limit; coverage is incomplete")
            self.interpolated_values.update(interpolated)

    def _unbind(self, name, external=False):
        self.aliases[name] = ""
        self.external_scopes[-1][name] = external
        self.object_types.pop(name, None)
        self.static_values.discard(name)
        self.literal_values.pop(name, None)
        self.interpolated_values.discard(name)

    def add(self, rule_id, node, confidence="medium", detail=None):
        self.findings.add(rule_id, node.lineno, getattr(node, "end_lineno", node.lineno), confidence, detail)

    def external(self, node):
        self._charge()
        if node is None:
            return False
        if isinstance(node, ast.Call):
            for name in self.names(node.func):
                if name in {"input", "sys.stdin.read", "sys.stdin.readline"}:
                    return True
                if name.startswith(("request.", "req.", "flask.request.")):
                    return True
        if isinstance(node, ast.Name):
            for scope in reversed(self.external_scopes):
                if node.id in scope:
                    return scope[node.id]
            return node.id in _EXTERNAL_NAMES
        return any(self.external(child) for child in ast.iter_child_nodes(node))

    def visit_Import(self, node):
        for alias in node.names:
            target = alias.asname or alias.name.split(".")[0]
            self._unbind(target)
            self.aliases[target] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:
                target = alias.asname or alias.name
                self._unbind(target)
                self.aliases[target] = node.module + "." + alias.name

    def visit_FunctionDef(self, node):
        for expression in node.decorator_list + node.args.defaults + [item for item in node.args.kw_defaults if item is not None]:
            self.visit(expression)
        annotations = [item.annotation for item in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        annotations += [item.annotation for item in (node.args.vararg, node.args.kwarg) if item is not None]
        for expression in annotations + [node.returns]:
            if expression is not None:
                self.visit(expression)
        self._unbind(node.name)
        self._function_scope(node.args, node.body)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _function_scope(self, arguments, body):
        saved = self._state()
        class_outer = self.class_outer_state
        if class_outer is not None:
            # Unqualified method names resolve in enclosing lexical scope,
            # never in the class attribute namespace.
            self._restore(class_outer)
        self.class_outer_state = None
        self.external_scopes.append({})
        local_names, declared_outer = set(), set()

        def bindings(item):
            self._charge()
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                local_names.add(item.name)
                return
            if isinstance(item, ast.Lambda):
                return
            if isinstance(item, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return
            if isinstance(item, (ast.Global, ast.Nonlocal)):
                declared_outer.update(item.names)
            if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
                local_names.add(item.id)
            if isinstance(item, (ast.Import, ast.ImportFrom)):
                local_names.update(alias.asname or alias.name.split(".")[0] for alias in item.names)
            for child in ast.iter_child_nodes(item):
                bindings(child)

        for item in body:
            bindings(item)
        for name in local_names - declared_outer:
            self._unbind(name)
        args = arguments.posonlyargs + arguments.args + arguments.kwonlyargs
        args += [item for item in (arguments.vararg, arguments.kwarg) if item is not None]
        for arg in args:
            self._unbind(arg.arg, arg.arg in _EXTERNAL_NAMES)
        for item in body:
            self.visit(item)
        self._restore(saved)
        self.class_outer_state = class_outer

    def visit_Lambda(self, node):
        for expression in node.args.defaults + [item for item in node.args.kw_defaults if item is not None]:
            self.visit(expression)
        self._function_scope(node.args, [node.body])

    def visit_ClassDef(self, node):
        for expression in node.bases + node.decorator_list + [item.value for item in node.keywords]:
            self.visit(expression)
        self._unbind(node.name)
        saved = self._state()
        outer_class = self.class_outer_state
        self.class_outer_state = saved
        self.external_scopes.append({})
        for statement in node.body:
            self.visit(statement)
        self._restore(saved)
        self.class_outer_state = outer_class

    def _comprehension(self, node):
        saved = self._state()
        self.external_scopes.append({})
        for generator in node.generators:
            self.visit(generator.iter)
            self._assignment(generator.target, generator.iter, node)
            for condition in generator.ifs:
                self.visit(condition)
        for expression in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
            self.visit(expression)
        self._restore(saved)

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension

    def visit_If(self, node):
        self.visit(node.test)
        initial = self._state()
        for statement in node.body:
            self.visit(statement)
        yes = self._state()
        self._restore(initial)
        for statement in node.orelse:
            self.visit(statement)
        self._join([yes, self._state()])

    def visit_For(self, node):
        self.visit(node.iter)
        initial = self._state()
        self._assignment(node.target, node.iter, node)
        for statement in node.body:
            self.visit(statement)
        self._join([initial, self._state()])
        for statement in node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.visit(node.test)
        initial = self._state()
        for statement in node.body:
            self.visit(statement)
        self._join([initial, self._state()])
        for statement in node.orelse:
            self.visit(statement)

    def visit_Try(self, node):
        # An exception may occur after any statement in the try block. Keep
        # accumulated possible bindings for handlers without enumerating paths.
        possible = self._state()
        for statement in node.body:
            self.visit(statement)
            current = self._state()
            self._join([possible, current])
            possible = self._state()
            self._restore(current)
        for statement in node.orelse:
            self.visit(statement)
        alternatives = [self._state()]
        for handler in node.handlers:
            self._restore(possible)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self._unbind(handler.name)
            for statement in handler.body:
                self.visit(statement)
            if handler.name:
                self._unbind(handler.name)
            alternatives.append(self._state())
        self._join(alternatives)
        for statement in node.finalbody:
            self.visit(statement)

    visit_TryStar = visit_Try

    def _track_object(self, target, value):
        if not isinstance(target, ast.Name):
            return
        if isinstance(value, ast.Name) and value.id in self.object_types:
            self.object_types[target.id] = self.object_types[value.id]
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
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assignment(item.optional_vars, item.context_expr, node)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def _assignment(self, target, value, node):
        if isinstance(target, (ast.Tuple, ast.List)):
            values = value.elts if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts) else [value] * len(target.elts)
            # Every RHS element is read before any target is rebound.
            original = self._state()
            updates = []
            for element, item in zip(target.elts, values):
                self._restore(original)
                self._assignment(element, item, node)
                updates.append(self._state())
            self._restore(original)
            for element, update in zip(target.elts, updates):
                for child in ast.walk(element):
                    if not isinstance(child, ast.Name):
                        continue
                    for current, changed in ((self.aliases, update[0]), (self.external_scopes[-1], update[1][-1]),
                                             (self.object_types, update[2]), (self.literal_values, update[4])):
                        if child.id in changed:
                            current[child.id] = changed[child.id]
                        else:
                            current.pop(child.id, None)
                    for current, changed in ((self.static_values, update[3]), (self.interpolated_values, update[5])):
                        current.discard(child.id)
                        if child.id in changed:
                            current.add(child.id)
            return
        source, static, literal = self.external(value), self.immutable_static(value), self.literal(value)
        literals = self.literals(value)
        interpolation = self.interpolation(value)
        aliases = self.names(value)
        self._track_object(target, value)
        name = target.id if isinstance(target, ast.Name) else self.name(target)
        if isinstance(target, ast.Name):
            self.aliases[target.id] = aliases or ""
            self.external_scopes[-1][target.id] = source
            self.static_values.discard(target.id)
            self.literal_values.pop(target.id, None)
            self.interpolated_values.discard(target.id)
            if static:
                self.static_values.add(target.id)
                self.literal_values[target.id] = literals
            if interpolation:
                self.interpolated_values.add(target.id)
        key = name.rsplit(".", 1)[-1]
        if isinstance(target, ast.Subscript):
            literal_key = _constant(target.slice)
            if isinstance(literal_key, str):
                key = literal_key
        if isinstance(target, (ast.Subscript, ast.Attribute)):
            root = target.value
            while isinstance(root, (ast.Subscript, ast.Attribute)):
                root = root.value
            if isinstance(root, ast.Name):
                self.static_values.discard(root.id)
                self.literal_values.pop(root.id, None)
                if source:
                    self.external_scopes[-1][root.id] = True
        if _credential_literal(key, literal):
            self.add("AI010", node, "medium")
        if key == "NODE_TLS_REJECT_UNAUTHORIZED" and literal in ("0", 0):
            self.add("AI006", node, "high")
        if key == "DANGEROUSLY_OMIT_AUTH" and _inspector_nonempty(literal):
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
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)
            self._assignment(target, node.value, node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self.visit(node.target)
            self._assignment(node.target, node.value, node)
        self.visit(node.annotation)

    def visit_AugAssign(self, node):
        self.visit(node.target)
        self.visit(node.value)
        value = ast.BinOp(left=node.target, op=node.op, right=node.value)
        ast.copy_location(value, node)
        self._assignment(node.target, value, node)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self._assignment(node.target, node.value, node)

    def visit_Dict(self, node):
        values = {_constant(key): value for key, value in zip(node.keys, node.values)
                  if isinstance(key, ast.Constant) and isinstance(key.value, str)}
        for key, value_node in values.items():
            literal = self.literal(value_node)
            if key == "DANGEROUSLY_OMIT_AUTH" and _inspector_nonempty(literal):
                self.add("AI041", value_node, "high")
            if _credential_literal(key, literal):
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
        if self.literal(values.get("role")) in {"system", "developer"} and self.external(values.get("content")):
            self.add("AI032", values["content"])
        self.generic_visit(node)

    def _check_call(self, node, name):
        tail = name.rsplit(".", 1)[-1]
        keywords = {item.arg: item.value for item in node.keywords if item.arg is not None}
        first = node.args[0] if node.args else next((keywords[key] for key in
                ("args", "command", "cmd", "file", "filename", "path", "source", "sql", "query", "s") if key in keywords), None)
        value = lambda key: self.literal(keywords.get(key))
        matches = lambda key, expected: any(type(item) is type(expected) and item == expected for item in self.literals(keywords.get(key)))
        dynamic = first is not None and not self.static(first)
        if name == "os.putenv" and len(node.args) >= 2 and self.literal(node.args[0]) == "DANGEROUSLY_OMIT_AUTH" and _inspector_nonempty(self.literal(node.args[1])):
            self.add("AI041", node, "high")
        if name == "os.environ.update" and _inspector_nonempty(value("DANGEROUSLY_OMIT_AUTH")):
            self.add("AI041", keywords["DANGEROUSLY_OMIT_AUTH"], "high")
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and dynamic:
            self.add("AI001", node)
        if name.startswith("subprocess.") and tail in {"run", "Popen", "call", "check_call", "check_output"} and matches("shell", True) and dynamic:
            self.add("AI002", node, "high" if self.external(first) else "medium")
        if name == "asyncio.create_subprocess_shell" and dynamic:
            self.add("AI002", node, "high" if self.external(first) else "medium")
        if name.startswith("subprocess.") and isinstance(first, (ast.List, ast.Tuple)) and len(first.elts) >= 3:
            executable = self.literal(first.elts[0])
            option = self.literal(first.elts[1])
            if isinstance(executable, str) and PurePosixPath(executable).name in {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"} and option in {"-c", "-lc", "/c", "-Command"} and not self.static(first.elts[2]):
                self.add("AI002", node)
        if name in {"os.system", "os.popen"} and dynamic:
            self.add("AI003", node)
        if name in {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all", "ruamel.yaml.load"}:
            loader = keywords.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            safe_loaders = {module + "." + loader_name for module in ("yaml", "yaml.loader", "yaml.cyaml", "ruamel.yaml")
                            for loader_name in ("SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader")}
            loader_names = self.names(loader)
            if not loader_names or not loader_names.issubset(safe_loaders):
                self.add("AI004", node, "high" if "unsafe" in name else "medium")
        if name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads", "joblib.load"}:
            self.add("AI005", node)
        receiver = node.func.value.id if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) else None
        receiver_type = self.object_types.get(receiver)
        http_client = (name.startswith(("requests.", "httpx.", "urllib3.", "aiohttp."))
                       or receiver_type in {"requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession"})
        if ((matches("verify", False) and http_client)
                or (matches("cert_reqs", 0) and name.startswith(("urllib3.", "ssl."))) or (name == "aiohttp.TCPConnector" and matches("ssl", False))
                or name == "ssl._create_unverified_context"):
            self.add("AI006", node, "high")
        if any(_has_star(value(key)) for key in ("allow_origins", "origins", "origin")) or (tail == "CORS" and _has_star(value("resources"))):
            self.add("AI007", node, "high")
        if any(matches("host", host) for host in ("0.0.0.0", "::", "[::]")):
            self.add("AI008", node, "high")
        if matches("debug", True):
            self.add("AI009", node, "high")
        if name == "tempfile.mktemp":
            self.add("AI016", node, "high")
        if "jwt" in name.lower() and tail == "decode":
            options = value("options")
            algorithms = value("algorithms")
            has_none = isinstance(algorithms, (list, tuple, str)) and "none" in algorithms
            if (isinstance(options, dict) and options.get("verify_signature") is False) or matches("verify", False) or has_none:
                self.add("AI017", node, "high")
        request_function = name.startswith(("requests.", "httpx.", "urllib.request.")) and tail in {"get", "post", "put", "patch", "delete", "head", "options", "request", "urlopen", "Request"}
        request_function = request_function or name in {"aiohttp.ClientSession.get", "aiohttp.ClientSession.post"}
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
        if name == "torch.load" and matches("weights_only", False):
            self.add("AI035", node, "high")
        if name.endswith("load_model") and matches("safe_mode", False):
            self.add("AI035", node, "high")
        if tail in {"execute", "executemany", "executescript"} and first is not None and self.interpolation(first):
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
            literal = self.literal(val_node)
            if _credential_literal(key, literal):
                self.add("AI010", val_node)
            if _norm(key) in _AUTH_DISABLED and matches(key, False):
                self.add("AI026", val_node)
            if _norm(key) in _WILDCARD_PERMISSION_KEYS and _has_star(literal):
                self.add("AI027", val_node)
            if _norm(key) in _PASSTHROUGH_KEYS and matches(key, True):
                self.add("AI028", val_node)
            if _norm(key) == "autoapprove" and _unrestricted_approval(literal):
                self.add("AI031", val_node, "high")
    def visit_Call(self, node):
        for name in sorted(self.names(node.func) or [""]):
            self._check_call(node, name)
        self.generic_visit(node)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.attr in {"append", "extend", "insert", "update", "add", "setdefault"}:
            receiver = node.func.value.id
            self.static_values.discard(receiver)
            self.literal_values.pop(receiver, None)
            if any(self.external(arg) for arg in node.args) or any(self.external(item.value) for item in node.keywords):
                self.external_scopes[-1][receiver] = True


def _json_analysis(findings, text, path):
    try:
        data = _load_source_json(text)
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
            if _credential_literal(key, item):
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
            if key == "DANGEROUSLY_OMIT_AUTH" and _inspector_nonempty(item):
                add("AI041", offset, "high")
            if norm in {"alloworigins", "origins", "corsorigins"} and _has_star(item):
                add("AI007", offset, "high")
            if norm == "host" and item in ("0.0.0.0", "::", "[::]"):
                add("AI008", offset, "high")
            if norm == "debug" and item is True:
                add("AI009", offset, "high")
            if norm in {"privileged", "allowprivilegeescalation"} and item is True:
                add("AI022", offset, "high")
            if (norm in {"hostpid", "hostnetwork"} and item is True) or (norm in {"networkmode", "pid"} and item == "host"):
                add("AI042", offset, "high")
            if isinstance(item, str) and any(socket in item for socket in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock")):
                add("AI023", offset, "high")
            container_context = any(_norm(parent) in {"containers", "initcontainers", "ephemeralcontainers", "services"} for parent in parents)
            if norm == "image" and container_context and isinstance(item, str) and not re.search(r"@sha256:[a-fA-F0-9]{64}$", item) and "${" not in item:
                add("AI024", offset, "low")
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
                if isinstance(args, list) and any(_unpinned_package(spec) for spec in _runner_packages(item, args)):
                    add("AI018", offset, "high")
            if PurePosixPath(path).name == "package.json" and key in {"dependencies", "devDependencies", "optionalDependencies"} and isinstance(item, dict):
                for package, version in item.items():
                    if isinstance(version, str) and not _exact_npm_version(version) and not version.startswith(("file:", "workspace:", "link:")):
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


class _JSToken:
    """Small lexical token; templates keep their executable interpolation tokens."""
    __slots__ = ("kind", "value", "start", "end", "children")

    def __init__(self, kind, value, start, end, children=()):
        self.kind, self.value, self.start, self.end = kind, value, start, end
        self.children = children


def _js_tokens(text):
    """Tokenize without executing code or treating string/regex bodies as code.

    This is a bounded lexer, not a JS/TS parser. Regex-vs-division recognition is
    contextual; unusual syntax, escaped identifiers and cross-module data flow
    still require a language-aware/manual review. Nested templates are bounded.
    """
    size = len(text)

    def quoted(index, quote):
        start, value = index, []
        index += 1
        while index < size:
            char = text[index]
            if char == quote:
                return _JSToken("string", "".join(value), start, index + 1), index + 1
            if char == "\\" and index + 1 < size:
                index += 1
                escaped = text[index]
                if escaped in {"x", "u"}:
                    width = 2 if escaped == "x" else 4
                    raw = text[index + 1:index + 1 + width]
                    if len(raw) == width and re.fullmatch(r"[0-9a-fA-F]+", raw):
                        value.append(chr(int(raw, 16)))
                        index += width + 1
                        continue
                value.append({"n": "\n", "r": "\r", "t": "\t", "\n": "", "\r": ""}.get(escaped, escaped))
            else:
                value.append(char)
            index += 1
        return _JSToken("unknown", "", start, index), index

    def scan(index=0, template_expression=False, depth=0):
        result, braces, paren_contexts = [], 0, []
        control_close = False
        while index < size:
            char, start = text[index], index
            if char.isspace():
                index += 1
                continue
            if text.startswith("//", index):
                index = text.find("\n", index)
                index = size if index < 0 else index
                continue
            if text.startswith("/*", index):
                end = text.find("*/", index + 2)
                index = size if end < 0 else end + 2
                continue
            if char in "\"'":
                token, index = quoted(index, char)
                result.append(token)
                continue
            if char == "`":
                index += 1
                children = []
                value = []
                terminated = False
                while index < size:
                    if text[index] == "\\" and index + 1 < size:
                        value.append(text[index + 1])
                        index += 2
                    elif text[index] == "`":
                        index += 1
                        terminated = True
                        break
                    elif text.startswith("${", index):
                        if depth >= 64:
                            # Never classify a truncated template as static.
                            children.append([_JSToken("unknown", "", index, size)])
                            index = size
                            break
                        child, index = scan(index + 2, True, depth + 1)
                        children.append(child)
                    else:
                        value.append(text[index])
                        index += 1
                kind = "template" if terminated else "unknown"
                result.append(_JSToken(kind, "".join(value), start, index, children))
                continue
            # A slash in an operand position starts a regex literal. Its body is
            # inert, including apparent calls, comments and character classes.
            previous = result[-1].value if result else None
            regex_position = previous is None or previous == ")" and control_close or previous in {
                "=", "(", "[", "{", ",", ":", ";", "!", "?", "&&", "||",
                "=>", "return", "throw", "case", "yield", "await", "??",
            }
            if char == "/" and regex_position:
                cursor, in_class = index + 1, False
                while cursor < size and text[cursor] not in "\r\n":
                    if text[cursor] == "\\":
                        cursor += 2
                        continue
                    if text[cursor] == "[":
                        in_class = True
                    elif text[cursor] == "]":
                        in_class = False
                    elif text[cursor] == "/" and not in_class:
                        cursor += 1
                        while cursor < size and text[cursor].isalpha():
                            cursor += 1
                        result.append(_JSToken("regex", "", index, cursor))
                        index = cursor
                        break
                    cursor += 1
                if index != start:
                    continue
            if char.isalpha() or char in "_$":
                index += 1
                while index < size and (text[index].isalnum() or text[index] in "_$"):
                    index += 1
                result.append(_JSToken("identifier", text[start:index], start, index))
                continue
            if char.isdigit():
                index += 1
                while index < size and (text[index].isalnum() or text[index] in "._"):
                    index += 1
                result.append(_JSToken("number", text[start:index], start, index))
                continue
            if char == "}" and template_expression and not braces:
                return result, index + 1
            if char == "{":
                braces += 1
            elif char == "}":
                braces -= 1
            pair = text[index:index + 2]
            value = pair if pair in {"=>", "?.", "&&", "||", "??", "==", "!=", "++", "--", "+=", "-=", "**"} else char
            index += len(value)
            if value == "(":
                paren_contexts.append(previous)
            elif value == ")":
                control_close = bool(paren_contexts and paren_contexts.pop() in {"if", "while", "for", "with", "switch", "catch"})
            result.append(_JSToken("punctuation", value, start, index))
        return result, index

    return scan()[0]


def _js_pairs(tokens):
    pairs, stack = {}, []
    for index, token in enumerate(tokens):
        if token.kind != "punctuation":
            continue
        if token.value in {"(", "[", "{"}:
            stack.append((token.value, index))
        elif token.value in {")", "]", "}"}:
            if stack and stack[-1][0] == {")": "(", "]": "[", "}": "{"}[token.value]:
                _, opening = stack.pop()
                pairs[opening] = index
                pairs[index] = opening
    return pairs


def _js_static(tokens):
    """Recognize literal-only expressions; never infer safety from variable names."""
    if not tokens:
        return False
    pairs = _js_pairs(tokens)
    while tokens and tokens[0].value == "(" and pairs.get(0) == len(tokens) - 1:
        tokens = tokens[1:-1]
        pairs = _js_pairs(tokens)
    if len(tokens) == 1:
        token = tokens[0]
        return token.kind in {"string", "number"} or (
            token.kind == "template" and all(_js_static(child) for child in token.children)) or (
            token.kind == "identifier" and token.value in {"true", "false", "null", "undefined"})
    # String concatenation of fixed literals remains fixed. This does not fold
    # calls, identifiers, member access, conditionals or arbitrary operators.
    return all(_js_static(tokens[index:index + 1]) if index % 2 == 0 else tokens[index].kind == "punctuation" and tokens[index].value == "+"
               for index in range(len(tokens))) and len(tokens) % 2 == 1


def _js_external(tokens, derived=()):
    direct = {"userInput", "userUrl", "userPath", "user_input", "user_url", "user_path",
              "toolInput", "toolOutput", "toolResult", "tool_input", "tool_output", "tool_result"}
    for index, token in enumerate(tokens):
        if token.kind == "identifier" and (token.value in direct or token.value in derived):
            return True
        if token.value in {"req", "request"} and index + 2 < len(tokens):
            if tokens[index + 1].value in {".", "?.", "["} and tokens[index + 2].value in {"body", "query", "params"}:
                return True
        if any(_js_external(child, derived) for child in token.children):
            return True
    return False


def _js_analysis(findings, text):
    """Bounded lexical JS/TS analysis with literal and local alias awareness."""
    tokens = _js_tokens(text)

    def analyze(tokens, inherited=None, derived=None):
        aliases = dict(inherited or {"eval": "eval", "Function": "function"})
        external_names = set(derived or ())
        scopes, arrow_scopes = [], []
        pairs = _js_pairs(tokens)
        count = len(tokens)

        def value(index):
            return tokens[index].value if 0 <= index < count else ""

        def expression_end(start, closing=None):
            cursor = start
            while cursor < count and (closing is None or cursor < closing):
                if tokens[cursor].kind == "punctuation" and value(cursor) in {",", ";", "}"}:
                    break
                if cursor in pairs and value(cursor) in {"(", "[", "{"}:
                    cursor = pairs[cursor] + 1
                else:
                    # ASI-separated declarations/expressions must not swallow
                    # the next statement; operators and member continuations do.
                    if cursor > start:
                        if tokens[cursor].kind == "identifier" and value(cursor) in {"const", "let", "var", "return", "import", "function"}:
                            break
                        prior = tokens[cursor - 1]
                        newline = "\n" in text[prior.end:tokens[cursor].start]
                        completed = prior.kind in {"string", "number", "template"} or prior.value in {")", "]", "++", "--"} or prior.kind == "identifier" and prior.value not in {"new", "await", "typeof", "void", "delete", "instanceof", "in"}
                        starts = tokens[cursor].kind in {"identifier", "string", "number", "template"} and value(cursor) not in {"as", "in", "instanceof", "satisfies"}
                        if newline and completed and starts:
                            break
                    cursor += 1
            return cursor

        def args(opening):
            closing = pairs.get(opening)
            if closing is None:
                return [], opening
            result, start = [], opening + 1
            cursor = start
            while cursor < closing:
                if tokens[cursor].kind == "punctuation" and value(cursor) == ",":
                    result.append(tokens[start:cursor])
                    start = cursor + 1
                elif cursor in pairs and value(cursor) in {"(", "[", "{"}:
                    cursor = pairs[cursor]
                cursor += 1
            if start < closing:
                result.append(tokens[start:closing])
            return result, closing

        def resolve(start):
            """Resolve only known local aliases and explicit module properties."""
            if start >= count or tokens[start].kind != "identifier":
                return None, start
            name, end = value(start), start + 1
            kind = aliases.get(name)
            if name == "require" and name not in aliases and value(end) == "(":
                arguments, closing = args(end)
                if len(arguments) == 1 and len(arguments[0]) == 1 and arguments[0][0].kind == "string" and arguments[0][0].value in {"child_process", "node:child_process"}:
                    kind, end = "namespace", closing + 1
            while kind and end < count:
                if value(end) in {".", "?."} and end + 1 < count and tokens[end + 1].kind == "identifier":
                    member, next_end = value(end + 1), end + 2
                elif value(end) == "[" and pairs.get(end) == end + 2 and tokens[end + 1].kind == "string":
                    member, next_end = value(end + 1), end + 3
                else:
                    break
                kind = "shell" if kind == "namespace" and member in {"exec", "execSync"} else None
                end = next_end
            if value(end) == "?." and value(end + 1) == "(":
                end += 1
            return kind, end

        def emit(rule, start, end=None, confidence="medium"):
            findings.offset(rule, tokens[start].start,
                            tokens[end if end is not None else start].end, confidence)

        index = 0
        while index < count:
            while arrow_scopes and index >= arrow_scopes[-1][0]:
                _, aliases, external_names = arrow_scopes.pop()
            token, word = tokens[index], value(index)
            previous = value(index - 1)
            for child in token.children:
                analyze(child, aliases, external_names)
            if token.kind == "identifier" and word == "import":
                # Accept genuine ES imports only, with their literal module token.
                end = index + 1
                while end < count and value(end) != ";" and end - index < 200:
                    if value(end) == "from" and end + 1 < count and tokens[end + 1].kind == "string":
                        child_process = value(end + 1) in {"child_process", "node:child_process"}
                        if value(index + 1) == "{":
                            cursor = index + 2
                            while cursor < end and value(cursor) != "}":
                                source = value(cursor)
                                local = value(cursor + 2) if value(cursor + 1) == "as" else source
                                if child_process and source in {"exec", "execSync"}:
                                    aliases[local] = "shell"
                                elif local in aliases or local == "require":
                                    aliases[local] = None
                                cursor += 3 if value(cursor + 1) == "as" else 1
                                if value(cursor) == ",":
                                    cursor += 1
                        else:
                            local = value(index + 3) if value(index + 1) == "*" else value(index + 1)
                            if child_process:
                                aliases[local] = "namespace"
                            elif local in aliases or local == "require":
                                aliases[local] = None
                        index = end + 2
                        break
                    end += 1
                if index == end + 2:
                    continue
            if token.kind == "punctuation" and word == "{":
                scopes.append((aliases.copy(), external_names.copy()))
            elif token.kind == "punctuation" and word == "}" and scopes:
                aliases, external_names = scopes.pop()
            # Declarations and direct reassignment establish/kill aliases. This
            # intentionally does not claim whole-program or interprocedural flow.
            if token.kind == "identifier" and value(index + 1) == "=" and previous not in {".", "?."}:
                end = expression_end(index + 2)
                kind, resolved_end = resolve(index + 2)
                if kind and resolved_end == end:
                    aliases[word] = kind
                elif word in aliases or word == "require":
                    aliases[word] = None
                if _js_external(tokens[index + 2:end], external_names):
                    external_names.add(word)
                else:
                    external_names.discard(word)
            if word in {"const", "let", "var"} and value(index + 1) == "{":
                closing = pairs.get(index + 1)
                if closing and value(closing + 1) == "=":
                    kind, _ = resolve(closing + 2)
                    cursor = index + 2
                    while cursor < closing:
                        source = value(cursor)
                        local = value(cursor + 2) if value(cursor + 1) == ":" else source
                        if kind == "namespace" and source in {"exec", "execSync"}:
                            aliases[local] = "shell"
                        elif local in aliases or local == "require":
                            aliases[local] = None
                        cursor += 3 if value(cursor + 1) == ":" else 1
                        if value(cursor) == ",":
                            cursor += 1
            if token.kind == "identifier" and word == "function" and tokens[index + 1:index + 2] and tokens[index + 1].kind == "identifier":
                aliases[value(index + 1)] = None
            # Arrow expression parameters have a scope even without braces.
            if token.kind == "punctuation" and word == "=>" and value(index + 1) != "{":
                end = expression_end(index + 1)
                arrow_scopes.append((end, aliases.copy(), external_names.copy()))
                opening = pairs.get(index - 1) if previous == ")" else None
                parameters = tokens[opening + 1:index - 1] if opening is not None else tokens[index - 1:index]
                for parameter in parameters:
                    if parameter.kind == "identifier":
                        aliases[parameter.value] = None
                        external_names.discard(parameter.value)
            # Function parameters are scoped shadows, not imports or builtin eval.
            if token.kind == "punctuation" and word == "{" and previous in {")", "=>"}:
                opening = pairs.get(index - 1) if previous == ")" else pairs.get(index - 2) if value(index - 2) == ")" else None
                if opening is not None:
                    before = value(opening - 1)
                    is_function = previous == "=>" or before == "function" or value(opening - 2) == "function"
                    if is_function:
                        for parameter in tokens[opening + 1:pairs[opening]]:
                            if parameter.kind == "identifier":
                                aliases[parameter.value] = None
                                external_names.discard(parameter.value)
                elif previous == "=>" and index >= 2 and tokens[index - 2].kind == "identifier":
                    aliases[value(index - 2)] = None
                    external_names.discard(value(index - 2))

            kind, opening = resolve(index) if previous not in {".", "?.", "function"} else (None, index)
            if value(opening) == "(" and previous not in {".", "?.", "function"}:
                arguments, closing = args(opening)
                if kind == "shell" and arguments and not _js_static(arguments[0]):
                    emit("AI012", index, closing)
                if kind in {"eval", "function"} and arguments:
                    relevant = arguments[:1] if kind == "eval" else arguments
                    if any(not _js_static(argument) for argument in relevant):
                        emit("AI013", index - 1 if previous == "new" else index, closing)

            # Property configuration: keys are executable object members, while
            # string values remain data. Quoted keys are supported explicitly.
            if token.kind in {"identifier", "string"} and value(index + 1) == ":":
                setting = value(index + 2)
                boolean = tokens[index + 2].kind == "identifier" if index + 2 < count else False
                if word == "rejectUnauthorized" and boolean and setting == "false": emit("AI006", index, index + 2, "high")
                if word in {"auth", "authentication", "requireAuth", "authEnabled"} and boolean and setting == "false": emit("AI026", index, index + 2)
                if word in {"tokenPassthrough", "allowTokenPassthrough", "forwardAccessToken", "forwardAuthorization"} and boolean and setting == "true": emit("AI028", index, index + 2, "high")
                if word == "dangerouslyAllowBrowser" and boolean and setting == "true": emit("AI030", index, index + 2, "high")
                if word in {"dangerouslySkipPermissions", "bypassPermissions", "autoApproveAll", "autoApprove", "auto_approve"} and boolean and setting == "true": emit("AI031", index, index + 2, "high")
                if word == "host" and setting in {"0.0.0.0", "::"}: emit("AI008", index, index + 2, "high")
                literals = [tokens[index + 2]] if index + 2 < count else []
                if setting == "[" and index + 2 in pairs:
                    literals = tokens[index + 3:pairs[index + 2]]
                if any(item.kind == "string" and item.value == "*" for item in literals):
                    if word in {"origin", "origins", "allowOrigins"}: emit("AI007", index, index + 2, "high")
                    if word in {"allowedTools", "toolAllowlist", "permissions", "allowedResources"}: emit("AI027", index, index + 2, "high")
                    if word in {"autoApprove", "auto_approve"}: emit("AI031", index, index + 2, "high")
                if word == "algorithms" and any(item.kind == "string" and item.value == "none" for item in literals): emit("AI017", index, index + 2, "high")
            if word == "NODE_TLS_REJECT_UNAUTHORIZED":
                equal = index + 2 if value(index + 1) == "]" else index + 1
                if value(equal) == "=" and value(equal + 1) in {"0", "0.0"}:
                    emit("AI006", index, equal + 1, "high")
            if word == "DANGEROUSLY_OMIT_AUTH" and token.kind in {"identifier", "string"}:
                operator = index + 2 if value(index + 1) == "]" else index + 1
                if value(operator) in {":", "="}:
                    end = expression_end(operator + 1)
                    setting = tokens[operator + 1:end]
                    # Known literal object/config strings and process.env
                    # setters only. Node stringifies even false, 0, null and
                    # undefined on assignment to process.env; delete is unset.
                    receiver = (previous == "." and value(index - 2) == "env" and value(index - 3) == "." and value(index - 4) == "process"
                                or previous == "[" and value(index - 2) == "env" and value(index - 3) == "." and value(index - 4) == "process")
                    nonempty = len(setting) == 1 and setting[0].kind in {"string", "template"} and not setting[0].children and bool(setting[0].value)
                    scalar_env = receiver and value(operator) == "=" and len(setting) == 1 and (setting[0].kind == "number" or setting[0].kind == "identifier" and setting[0].value in {"true", "false", "null", "undefined"})
                    if nonempty or scalar_env:
                        emit("AI041", index, max(index, end - 1), "high")

            # Calls use balanced argument ranges rather than a line-length regex.
            if token.kind == "identifier" and value(index + 1) == "(":
                arguments, closing = args(index + 1)
                first = arguments[0] if arguments else []
                receiver = value(index - 2) if previous in {".", "?."} else ""
                if ((word == "fetch" and not receiver) or (word in {"get", "post", "request"} and receiver == "axios")) and _js_external(first, external_names): emit("AI014", index, closing)
                if word in {"readFile", "readFileSync", "writeFile", "writeFileSync", "unlink", "rm"} and (not receiver or receiver == "fs" or receiver == "promises" and value(index - 4) == "fs") and _js_external(first, external_names): emit("AI015", index, closing)
                if word == "listen" and len(arguments) > 1 and len(arguments[1]) == 1 and arguments[1][0].value in {"0.0.0.0", "::"}: emit("AI008", index, closing, "high")
                if receiver in {"console", "logger", "log"} and word in {"log", "info", "warn", "error", "debug"}:
                    def secret_reference(items):
                        for offset, item in enumerate(items):
                            field = item.kind == "identifier" or item.kind == "string" and offset > 0 and items[offset - 1].value == "["
                            if field and _is_secret_key(item.value) or any(secret_reference(child) for child in item.children):
                                return True
                        return False
                    if any(secret_reference(argument) for argument in arguments): emit("AI033", index, closing)
                if previous in {".", "?."} and word in {"query", "execute"} and first and not _js_static(first) and any(item.kind == "template" and item.children or item.value == "+" for item in first): emit("AI036", index, closing)
                if word == "insertAdjacentHTML" and len(arguments) > 1 and not _js_static(arguments[1]): emit("AI040", index, closing)
            if word in {"innerHTML", "outerHTML"} and value(index + 1) == "=":
                end = expression_end(index + 2)
                if not _js_static(tokens[index + 2:end]): emit("AI040", index, max(index, end - 1))
            if word == "dangerouslySetInnerHTML" and value(index + 1) == "=":
                end = expression_end(index + 2)
                for cursor in range(index + 2, end - 1):
                    if value(cursor) == "__html" and value(cursor + 1) == ":":
                        value_end = expression_end(cursor + 2)
                        if not _js_static(tokens[cursor + 2:value_end]): emit("AI040", index, max(index, value_end - 1))
            # Match role/content in the same object regardless of field ordering.
            if token.kind == "punctuation" and word == "{" and index in pairs:
                fields, cursor = {}, index + 1
                while cursor < pairs[index]:
                    if value(cursor + 1) == ":" and tokens[cursor].kind in {"identifier", "string"}:
                        end = expression_end(cursor + 2, pairs[index])
                        fields[value(cursor)] = tokens[cursor + 2:end]
                        cursor = end
                    elif cursor in pairs and value(cursor) in {"{", "[", "("}:
                        cursor = pairs[cursor]
                    cursor += 1
                role = fields.get("role", [])
                if len(role) == 1 and role[0].kind == "string" and role[0].value in {"system", "developer"} and _js_external(fields.get("content", []), external_names): emit("AI032", index, pairs[index])
            index += 1

    analyze(tokens)


def _generic_analysis(findings, text, path, suffix):
    clean = _strip_comments(text) if suffix in _JS_SUFFIXES or suffix == ".jsonc" else text
    _regex(findings, clean, "AI011", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", confidence="high",
           predicate=lambda match: _private_key_body(clean, match.end()))
    _regex(findings, clean, "AI034", r"https?://[^\s'\"<>]{1,1500}[?&](?:access_token|api_key|apikey|client_secret|token)=(?P<secret>[^\s'\"&<>]{8,500})", re.I,
           predicate=lambda match: not _placeholder(match.group("secret")))
    # Generic secrets cover dotenv, YAML, JS and shell; Python/JSON have syntax-aware checks.
    if suffix not in {".py", ".pyi", ".json", ".jsonc"}:
        secret_pattern = r"\b(?P<key>[A-Za-z_][A-Za-z0-9_-]{0,80})\s*[:=]\s*(?P<quote>['\"])(?P<secret>[^'\"\r\n]{8,500})(?P=quote)"
        _regex(findings, clean, "AI010", secret_pattern,
               predicate=lambda match: _credential_literal(match.group("key"), match.group("secret")))
        if suffix in {".env", ".yaml", ".yml", ".ini", ".cfg", ".toml"} or PurePosixPath(path).name.startswith(".env"):
            _regex(findings, clean, "AI010", r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_-]{0,80})\s*[:=]\s*(?P<secret>[^\s'\"#][^\s#]{7,499})\s*(?:#.*)?$", re.M,
                   predicate=lambda match: _credential_literal(match.group("key"), match.group("secret")))
    # Standalone recognizable key formats supplement semantic key names.
    _regex(findings, clean, "AI010", r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,255}|sk-(?:proj-)?[A-Za-z0-9_-]{24,255})\b")
    _regex(findings, clean, "AI010", r"\b(?:Authorization|authorization)['\"]?\s*[:=]\s*['\"]Bearer\s+(?P<secret>[A-Za-z0-9._~+/-]{12,500})['\"]",
           predicate=lambda match: not _placeholder(match.group("secret")))
    if suffix in _CONFIG_SUFFIXES or suffix in {".sh", ".bash", ".zsh", ".ps1"} or "dockerfile" in PurePosixPath(path).name.lower():
        _regex(findings, clean, "AI019", r"\b(?:curl|wget)\b[^\n|]{1,1000}\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b", confidence="high")
        _regex(findings, clean, "AI031", r"--(?:dangerously-skip-permissions|dangerously-bypass-approvals-and-sandbox|yolo)\b", confidence="high")
    _inspector_env_assignments(findings, clean, path, suffix)
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
               lambda match: not re.search(r"@sha256:[a-fA-F0-9]{64}$", match.group("image")) and "${" not in match.group("image"))
        if "/.github/workflows/" in "/" + path.replace("\\", "/"):
            _regex(findings, clean, "AI020", r"^\s*-?\s*uses\s*:\s*['\"]?(?P<action>[^\s'\"#]+)", re.M, "high",
                   lambda match: not match.group("action").startswith(("./", "docker://")) and not re.search(r"@[a-fA-F0-9]{40}$", match.group("action")))
    if "dockerfile" in PurePosixPath(path).name.lower():
        _docker_final_root(findings, clean)
        stage_names = set()
        for match in re.finditer(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?", clean, re.M | re.I):
            image = match.group("image")
            if image.lower() != "scratch" and image not in stage_names and not re.search(r"@sha256:[a-fA-F0-9]{64}$", image) and "$" not in image:
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
            _load_source_json(_strip_comments(text) if suffix == ".jsonc" else text)
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
