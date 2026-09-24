"""Bounded inspection of agent-facing instructions; never execute their contents.

These are evidence predicates, not a malicious-package classifier. The parser only
inspects declared instruction surfaces and literal tool metadata. Human intent,
dynamic descriptions, remote resources and actual runtime effects remain unknown.
"""
from __future__ import annotations

import ast
import base64
import binascii
import html
import json
import re
import shlex
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath

MAX_DOCUMENT = 262144
MAX_METADATA_DOCUMENT = 1000000
MAX_SEGMENT = 8192
MAX_SEGMENTS = 2048
MAX_DECODED = 8192
MAX_ENCODINGS = 32
INSTRUCTION_NAMES = {"skill.md", "agents.md", "claude.md", "gemini.md", "copilot-instructions.md"}
_JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


@dataclass
class Segment:
    text: str
    line: int
    surface: str
    read_only: bool = False


def is_instruction_path(path):
    """Recognize conventional agent instruction files and named skill trees.

    Arbitrarily named Markdown references outside these conventions require the
    caller's skill-root discovery (or explicit paths); this never follows links.
    """
    parts = PurePosixPath(path.replace("\\", "/"))
    return (parts.name.lower() in INSTRUCTION_NAMES
            or parts.name.lower().endswith(".instructions.md")
            or parts.suffix.lower() == ".mdc"
            or (parts.suffix.lower() == ".md"
                and any(part.lower() in {"skills", ".skills"} for part in parts.parts[:-1])))


def _normalize(text):
    text = html.unescape(unicodedata.normalize("NFKC", text))
    text = "".join(char for char in text if unicodedata.category(char) != "Cf")
    text = re.sub(r"<!--|-->|</?(?:system|developer|assistant|instructions)\s*>", "", text, flags=re.I)
    # Formatting may decorate directive words; underscores inside identifiers
    # remain useful to the sensitive-object predicate.
    text = re.sub(r"[`*]", "", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def _imperative(text, start):
    """Require an instruction clause, not a quoted discussion of an attack."""
    prefix = text[:start]
    boundary = max(prefix.rfind(char) for char in ".!?;:\n")
    clause = prefix[boundary + 1:].strip().lower()
    if re.search(r"\b(?:do not|don't|never|avoid|must not|should not|cannot|can't)\b", clause):
        return False
    if re.search(r"[\"'“‘]", clause):
        return False
    # A small operational-purpose grammar, not arbitrary prose before a verb.
    clause = re.sub(r"^for (?:the |a )?(?:support|diagnostic|debug) (?:bundle|report|package),\s*", "", clause)
    return bool(re.fullmatch(
        r"(?:[-+>\d.) ]*)?(?:(?:please|por favor|veuillez|bitte|you must|you should|always|first|then|next|now|also|silently|secretly|immediately|instead|important|system|developer|assistant)\s*[, -]?\s*)*",
        clause))


def _educational(text):
    # A narrowly labelled quotation/example is data. Unlabelled blocks remain
    # live instruction surfaces, including hidden HTML comments.
    return bool(re.match(
        r"\s*(?:[-*]\s*)?(?:example (?:attack|payload)|(?:attack|test|malicious|injection) (?:example|payload)|(?:do not|never) (?:follow|execute|obey|run) (?:this|the following)|(?:quoted|example) untrusted (?:text|content))\s*:",
        text, re.I))


_OVERRIDE = re.compile(r"\b(?:ignore|disregard|override|bypass|replace)\s+(?:(?:all|any|the|your|previous|prior|earlier|existing|higher[- ]priority|safety|security)\s+){0,6}(?:instructions?|system (?:prompt|message|instructions?)|developer (?:message|instructions?)|safety (?:policy|rules)|security (?:policy|rules))\b", re.I)
_TRANSFER = re.compile(r"\b(?:send|upload|post|transmit|forward|exfiltrate|attach|include|append)\b", re.I)
_READ = re.compile(r"\b(?:read|collect|extract|copy|retrieve|open|locate)\b", re.I)
_SENSITIVE = re.compile(r"(?:\b(?:api[_ -]?keys?|access[_ -]?tokens?|auth(?:entication)?[_ -]?tokens?|passwords?|credentials?|private[_ -]?keys?|secrets?|(?:login|password|credential) vault|credential store)\b|(?:~/|\$HOME/|/home/[^/ ]+/)?\.ssh/(?:id_rsa|id_ed25519)|(?<![\w])\.env\b|\bAWS_SECRET_ACCESS_KEY\b)", re.I)
_DESTINATION = re.compile(r"https?://[^\s<>\"']+|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.I)
_BYPASS = re.compile(r"\b(?:skip|bypass|disable|ignore)\s+(?:(?:all|any|the|user|human|security|tool|execution|required)\s+){0,5}(?:approvals?|confirmation|consent|permission (?:checks?|prompts?)|sandbox(?:ing)?)\b", re.I)
_HIDE = re.compile(r"\b(?:(?:do not|don't|never)\s+(?:tell|inform|notify|mention (?:this )?to)\s+(?:the )?user|(?:hide|conceal)\s+(?:this|the (?:action|operation|execution|transfer))\s+from\s+(?:the )?user)\b", re.I)
_ACTION = re.compile(r"\b(?:run|execute|delete|remove|overwrite|upload|send|post|transmit|install|modify|write|read|collect|extract)\b", re.I)
_DESTRUCTIVE = re.compile(r"\b(?:delete|remove|overwrite|modify|write|truncate|drop)\s+(?:(?:the|all|specified|selected|a|an|existing|user|target|database)\s+){0,5}(?:files?|directories|directory|records?|rows?|tables?|database|data|contents?|workspace|documents?)\b", re.I)
_BASE64 = re.compile(r"\b(?:base64(?:[- ]encoded)?(?:\s+(?:instructions?|payload))?\s*[:=]\s*|(?:decode|execute|follow|run)\s+(?:this\s+)?base64\s*[:=]?\s*)[`\"']?([A-Za-z0-9+/]{20,}={0,2})", re.I)
_LOCALIZED_OVERRIDE = re.compile(
    r"\b(?:ignor(?:a|e|en)|omite)\s+(?:(?:todas|todos|las|los|tus|sus)\s+){0,4}(?:instrucciones|directivas)\s+(?:anteriores|previas)\b"
    r"|\b(?:ignorez|ignorer)\s+(?:(?:toutes|les|vos)\s+){0,3}instructions\s+(?:pr[ée]c[ée]dentes|ant[ée]rieures)\b"
    r"|\bignoriere\s+(?:(?:alle|die|deine)\s+){0,3}(?:vorherigen|bisherigen|vorherige)\s+anweisungen\b", re.I)
_INVALIDATE_AUTHORITY = re.compile(r"\b(?:the |all )?(?:earlier|previous|prior|system|developer|higher[- ]priority) (?:directives|instructions|rules|messages) (?:are|is) (?:now )?(?:obsolete|invalid|superseded|no longer (?:valid|applicable))\b", re.I)
_REPLACE_AUTHORITY = re.compile(r"\b(?:the )?(?:sole|highest|final|only) authority (?:is|comes from) (?:now )?(?:this|the current) (?:tool description|skill|document|instructions)\b", re.I)
_CONDITIONAL_AUTHORITY = re.compile(
    r"\b(?:when|if) (?:the )?(?:system|developer) (?:message|instructions?|rules?) "
    r"(?:disagrees?|conflicts?) with (?:this|the current) (?:tool|skill|document|tool description),? "
    r"(?:then )?treat (?:this|the current) (?:tool|skill|document|tool description) as (?:the )?"
    r"(?:final|sole|highest|only) authority\b", re.I)
_ERASE_AUDIT = re.compile(
    r"\b(?:delete|remove|erase|clear|truncate) (?:the |all |these )?"
    r"(?:audit (?:logs?|trail)|security logs?|operation history) "
    r"so (?:that )?(?:the )?user (?:cannot|can't|won't|will not) (?:see|audit|review|trace)\b", re.I)


def _sensitive_object(text, verb_end):
    """Require a credential/file object, not a public discussion of secrets."""
    tail = text[verb_end:verb_end + 250]
    match = _SENSITIVE.search(tail)
    if not match:
        return False
    prefix = tail[:match.start()].strip().lower()
    if not re.fullmatch(r"(?:(?:the|all|any|a|an|your|user|raw|stored|collected|local|cloud|contents|content|of|file|files|entire|copy)\s*)*", prefix):
        return False
    return not re.match(r"\s+(?:names|identifiers|documentation|examples|hashes|guidelines)\b", tail[match.end():], re.I)


def _predicate_records(segment, value, detail=""):
    if _educational(value):
        return []
    records = []
    def add(rule, match, reason):
        line = segment.line + value.count("\n", 0, match.start())
        records.append((rule, line, "medium", "%s %s%s" % (segment.surface, reason, detail)))
    for match in _OVERRIDE.finditer(value):
        if _imperative(value, match.start()):
            add("AI043", match, "contains an explicit request to override higher-trust instructions; whether an agent follows it requires runtime validation.")
    for match in _LOCALIZED_OVERRIDE.finditer(value):
        tail = re.split(r"[.!?;\n]", value[match.end():], maxsplit=1)[0]
        if _imperative(value, match.start()) and not re.search(r"\b(?:nicht|jamais|nunca|no)\b", tail, re.I):
            add("AI043", match, "contains a recognized Spanish, French or German instruction-hierarchy override. This bounded language grammar is not general translation or proof of model compliance.")
    invalidations = [m for m in _INVALIDATE_AUTHORITY.finditer(value) if _imperative(value, m.start())]
    replacements = [m for m in _REPLACE_AUTHORITY.finditer(value) if _imperative(value, m.start())]
    for match in invalidations:
        if any(0 <= replacement.start() - match.end() <= 1200 for replacement in replacements):
            add("AI043", match, "invalidates higher-trust instructions and assigns sole authority to the current tool/skill text within the same bounded segment. The paired authority claims require contextual and runtime review.")
    for match in _CONDITIONAL_AUTHORITY.finditer(value):
        if _imperative(value, match.start()):
            add("AI043", match, "explicitly resolves a conflict with system/developer instructions in favor of the current tool or skill. Whether an agent honors this lower-trust authority claim requires runtime validation.")
    for match in _TRANSFER.finditer(value):
        if any(target.start() <= match.start() < target.end() for target in _DESTINATION.finditer(value)):
            continue  # A URL path such as /upload is data, not another verb.
        left, right = max(0, match.start() - 1000), min(len(value), match.end() + 1500)
        # A compound read-and-send instruction must begin with an imperative.
        direct = _imperative(value, match.start()) and _sensitive_object(value, match.end())
        reads = [item for item in _READ.finditer(value[:match.start()])
                 if item.start() >= left and _imperative(value, item.start())]
        # Only the nearest operative retrieval can supply the referent. A later
        # public-file retrieval must not inherit an earlier credential label.
        read = reads[-1] if reads else None
        linked_read = read is not None and _sensitive_object(value, read.end()) and bool(re.match(
            r"\s+(?:it|them|these|that|the (?:contents|data|credentials|keys|attachment)|(?:this|that) (?:file|attachment))\b",
            value[match.end():], re.I))
        # Explicit local negation of the transfer always wins over a prior read.
        before = value[max(left, match.start() - 30):match.start()]
        negated = bool(re.search(r"\b(?:do not|don't|never|must not|should not)\s*$", before, re.I))
        destination = bool(_DESTINATION.search(value[match.end():right]))
        if match.group().lower() in {'include', 'append'}:
            destination = destination and bool(re.search(r"\b(?:attachment|bundle|email|message|report|package)\b", value[match.end():right], re.I))
        if (direct or linked_read) and not negated and destination:
            add("AI044", match, "requests a sensitive object and an explicit network destination in the same bounded instruction. Authorization, destination ownership and actual transfer remain unverified.")
    for match in _BYPASS.finditer(value):
        if _imperative(value, match.start()):
            add("AI045", match, "explicitly requests bypassing an approval or execution boundary.")
    actions = [match for match in _ACTION.finditer(value) if _imperative(value, match.start())]
    for match in _HIDE.finditer(value):
        if actions and any(abs(action.start() - match.start()) < 2000 for action in actions):
            add("AI045", match, "combines an action instruction with concealment from the user. Review consent and require auditable tool execution.")
    for match in _ERASE_AUDIT.finditer(value):
        if _imperative(value, match.start()):
            add("AI045", match, "explicitly requests erasing audit evidence so the user cannot inspect the action. Authorization and actual execution remain unverified.")
    if segment.read_only:
        for match in _DESTRUCTIVE.finditer(value):
            if _imperative(value, match.start()):
                add("AI046", match, "declares readOnlyHint=true but describes a destructive operation. Annotations are untrusted hints; inspect implementation and enforce authorization independently.")
    return records


def _markdown(text, errors):
    segments, shell = [], []
    lines = text.splitlines()
    index = 0
    # Frontmatter is not broadly evaluated as executable configuration. Inspect
    # its text for instruction-bearing descriptions and its explicit tool grant.
    front_end = 0
    if lines and lines[0].strip() == "---":
        front_end = next((i for i, line in enumerate(lines[1:256], 1) if line.strip() == "---"), 0)
        if not front_end:
            errors.append("Skill/instruction frontmatter has no closing delimiter within 255 lines; permission-field coverage is incomplete.")
    while index < len(lines):
        line = lines[index]
        fence = re.match(r"^\s{0,3}(`{3,}|~{3,})([^`]*)$", line)
        if fence:
            marker, language = fence.group(1), fence.group(2).strip().lower()
            start, index = index + 1, index + 1
            while index < len(lines) and not re.match(r"^\s{0,3}" + re.escape(marker[0]) + "{" + str(len(marker)) + r",}\s*$", lines[index]):
                index += 1
            body = "\n".join(lines[start:index])
            lead = next((v for v in reversed(lines[max(0, start - 5):start - 1]) if v.strip()), "")
            example = _educational(lead) or bool(re.match(r"\s*(?:#{1,6}\s*)?(?:bad example|attack example|test payload|quoted example)\b", lead, re.I))
            if not example:
                segments.append(Segment(body, start + 1, "Agent instruction code block"))
                if language in {"sh", "shell", "bash", "zsh", "console"}:
                    shell.append((body, start + 1))
            if index == len(lines):
                errors.append("An agent instruction code fence is unclosed; its literal contents were inspected but document structure is ambiguous.")
            index += 1
            continue
        if not line.strip():
            index += 1
            continue
        start = index
        while index < len(lines) and lines[index].strip() and not re.match(r"^\s{0,3}(?:`{3,}|~{3,})", lines[index]):
            index += 1
        body = "\n".join(lines[start:index])
        # Blockquotes are still untrusted data, unless the document explicitly
        # instructs execution. Do not certify quoted attack examples as safe.
        if not all(not row.strip() or row.lstrip().startswith(">") for row in lines[start:index]):
            segments.append(Segment(body, start + 1, "Agent/skill instruction text"))
        elif _predicate_records(Segment(body, start + 1, "Quoted instruction"), _normalize(body)):
            errors.append("Quoted agent-facing text at line %s contains a risk directive; whether it is inert quoted data requires contextual review." % (start + 1))
    return segments, shell, front_end


def _shell_pipeline_records(body, line, errors):
    """Recognize a direct, single-line download-to-shell pipeline only."""
    records = []
    # A full shell grammar is deliberately out of scope. In particular, avoid
    # interpreting heredoc bodies or continued quoted strings as commands.
    if "<<" in body or "\\\n" in body:
        errors.append("An instruction shell block uses heredoc/continuation syntax; bootstrap-pipeline coverage is incomplete.")
        return records
    for offset, source in enumerate(body.splitlines()):
        try:
            lexer = shlex.shlex(source, posix=True, punctuation_chars="|;&<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            errors.append("An instruction shell block has ambiguous quoting at line %s; bootstrap coverage is incomplete." % (line + offset))
            # The next line may still be data in this unterminated quote.
            # Stop this small grammar instead of treating it as a new command.
            return records
        if tokens.count("|") != 1 or any(value in {";", "&", "&&", "||", ">", ">>", "<"} for value in tokens):
            continue
        split = tokens.index("|")
        left, right = tokens[:split], tokens[split + 1:]
        if right[:1] == ["sudo"]:
            right = right[1:]
        if not left or not right or PurePosixPath(right[0]).name not in {"sh", "bash", "zsh"}:
            continue
        if any(value not in {"-s", "-e", "-u", "-x", "--"} for value in right[1:]):
            continue
        executable = PurePosixPath(left[0]).name
        if executable not in {"curl", "wget"}:
            continue
        urls = [value for value in left[1:] if re.fullmatch(r"https?://[^\s]+", value)]
        if len(urls) != 1:
            continue
        options = [value for value in left[1:] if value not in urls]
        if executable == "curl":
            stdout = all(re.fullmatch(r"-[fsSL]+|--(?:fail|silent|show-error|location)", value) for value in options)
        else:
            stdout = any(re.fullmatch(r"-[qnv]*O-", value) or value == "--output-document=-" for value in options)
            stdout = stdout and all(re.fullmatch(r"-[qnv]*O-|-?[qnv]+|--(?:quiet|no-verbose|output-document=-)", value) for value in options)
        if stdout:
            records.append(("AI019", line + offset, "high", "An executable agent/skill shell fence sends a literal network download directly into a shell. No command was executed by this scan."))
    return records


def _literal(node, depth=0):
    if depth > 20:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _literal(node.left, depth + 1), _literal(node.right, depth + 1)
        if a is not None and b is not None and len(a) + len(b) <= MAX_SEGMENT:
            return a + b
    return None


def _python_segments(text, errors):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []  # The source analyzer reports its own parse error.
    segments, seen = [], set()
    def put(node, surface, read_only=False):
        value = _literal(node)
        if value is None:
            errors.append("Dynamic tool description at line %s was not resolved; instruction-threat checks require literal metadata." % node.lineno)
        elif (node.lineno, value, read_only) not in seen:
            seen.add((node.lineno, value, read_only))
            segments.append(Segment(value, node.lineno, surface, read_only))
    def name(node):
        return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
    def readonly(node):
        if not isinstance(node, ast.Call):
            return False
        annotation = next((kw.value for kw in node.keywords if kw.arg == "annotations"), None)
        if isinstance(annotation, ast.Dict):
            keys = [key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None for key in annotation.keys]
            if None in keys:
                errors.append("Expanded or computed Python tool annotations at line %s require contextual review." % annotation.lineno)
                return False
            values = {k.value: v for k, v in zip(annotation.keys, annotation.values) if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            value = values.get("readOnlyHint")
        elif isinstance(annotation, ast.Call) and name(annotation.func) == "ToolAnnotations":
            keys = [kw.arg for kw in annotation.keywords]
            if None in keys or len(keys) != len(set(keys)):
                errors.append("Expanded or duplicate ToolAnnotations arguments at line %s require contextual review." % annotation.lineno)
                return False
            value = next((kw.value for kw in annotation.keywords if kw.arg == "readOnlyHint"), None)
        else:
            value = None
        return isinstance(value, ast.Constant) and value.value is True
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = [item for item in node.decorator_list if name(item.func if isinstance(item, ast.Call) else item) == "tool"]
            if decorators:
                if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                    put(node.body[0].value, "Python tool docstring", any(readonly(item) for item in decorators))
        if not isinstance(node, ast.Call) or name(node.func) not in {"tool", "Tool", "register_tool"}:
            continue
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        if "description" in keywords:
            put(keywords["description"], "Python literal tool description", readonly(node))
    return segments


def _json_segments(text, errors):
    descriptors = []
    descriptor_count = 0
    schema_nodes = 0
    def schema_descriptions(schema):
        nonlocal schema_nodes
        pending = [schema]
        while pending:
            node = pending.pop()
            schema_nodes += 1
            if schema_nodes > 20000:
                if schema_nodes == 20001:
                    errors.append("Tool input-schema description inspection exceeded 20000 nodes; remaining schema instructions need review.")
                return
            if isinstance(node, dict):
                if isinstance(node.get('description'), str):
                    if len(descriptors) < MAX_SEGMENTS:
                        descriptors.append((node['description'], False, id(node)))
                    elif len(descriptors) == MAX_SEGMENTS:
                        errors.append("Tool metadata descriptions exceeded 2048 segments; remaining schema instructions need review.")
                # Only known schema subtrees; arbitrary example/const values
                # are data and must not become operative instructions.
                for key in ('properties', '$defs', 'definitions', 'patternProperties', 'dependentSchemas', 'dependencies'):
                    if isinstance(node.get(key), dict):
                        pending.extend(reversed(list(node[key].values())))
                for key in ('items', 'additionalItems', 'additionalProperties', 'unevaluatedProperties',
                            'unevaluatedItems', 'propertyNames', 'contentSchema', 'not', 'if', 'then', 'else', 'contains'):
                    if isinstance(node.get(key), dict):
                        pending.append(node[key])
                for key in ('allOf', 'anyOf', 'oneOf', 'prefixItems', 'items'):
                    if isinstance(node.get(key), list):
                        pending.extend(reversed(node[key]))
    def pairs(items):
        nonlocal descriptor_count
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        # Inspect each completed object during the bounded parse. Charge actual
        # tool descriptors, not ordinary dependency/translation nodes, so a large
        # unrelated JSON object cannot consume the descriptor traversal budget.
        if isinstance(result.get("name"), str) and any(key in result for key in ("inputSchema", "input_schema", "parameters")):
            descriptor_count += 1
            if descriptor_count > MAX_SEGMENTS:
                if descriptor_count == MAX_SEGMENTS + 1:
                    errors.append("Tool metadata inspection exceeded 2048 JSON descriptors; remaining descriptions need review.")
            elif isinstance(result.get("description"), str):
                annotations = result.get("annotations", {})
                readonly = isinstance(annotations, dict) and annotations.get("readOnlyHint") is True
                descriptors.append((result["description"], readonly, id(result)))
            elif result.get("description") is not None:
                errors.append("A structured tool description is not a literal string; instruction-threat coverage is incomplete.")
            if descriptor_count <= MAX_SEGMENTS:
                for key in ('inputSchema', 'input_schema', 'parameters'):
                    if isinstance(result.get(key), dict):
                        schema_descriptions(result[key])
        return result
    try:
        root = json.loads(text, object_pairs_hook=pairs)
    except (ValueError, RecursionError, MemoryError):
        return []
    if not descriptors:
        return []
    # Resolve description coordinates by their parsed object identity. Matching
    # text alone could incorrectly anchor a tool finding to an identical string
    # inside an earlier inert example/const or a different annotation scope.
    wanted = {identity for _, _, identity in descriptors}
    locations = {}
    stack, line, previous = [], 1, 0
    for match in re.finditer(r'"(?:[^"\\]|\\.)*"|[{}\[\],:]', text):
        line += text.count("\n", previous, match.start())
        previous = match.end()
        token = match.group()
        if token in {'{', '['}:
            if not stack:
                value = root
            else:
                parent = stack[-1]
                value = parent['value'][parent['key']]
            stack.append({'value': value, 'key': None if isinstance(value, dict) else 0,
                          'expects_key': isinstance(value, dict)})
        elif token in {'}', ']'}:
            stack.pop()
        elif token == ',' and stack:
            frame = stack[-1]
            if isinstance(frame['value'], dict):
                frame['expects_key'] = True
            else:
                frame['key'] += 1
        elif token.startswith('"') and stack:
            frame = stack[-1]
            if frame['expects_key']:
                frame['key'] = json.loads(token)
                frame['expects_key'] = False
            elif isinstance(frame['value'], dict) and frame['key'] == 'description' and id(frame['value']) in wanted:
                locations[id(frame['value'])] = line
    segments = []
    for value, readonly, identity in descriptors:
        line = locations.get(identity, 1)
        segments.append(Segment(value, line, "Structured tool description", readonly))
    return segments


def _js_segments(text, tokenize, errors):
    if tokenize is None:
        return []
    tokens = tokenize(text)
    pairs, stack = {}, []
    for i, token in enumerate(tokens):
        if token.kind == "punctuation" and token.value in {"(", "[", "{"}:
            stack.append((token.value, i))
        elif token.kind == "punctuation" and token.value in {")", "]", "}"} and stack and stack[-1][0] == {")": "(", "]": "[", "}": "{"}[token.value]:
            _, start = stack.pop()
            pairs[start] = i
    def chunks(start, end):
        result, first, i = [], start, start
        while i < end:
            if tokens[i].value == "," and tokens[i].kind == "punctuation":
                result.append((first, i)); first = i + 1
            i = pairs.get(i, i) + 1
        if first < end:
            result.append((first, end))
        return result
    def props(start, end):
        result = {}
        if start >= end or tokens[start].value != "{" or pairs.get(start) != end - 1:
            return result
        for first, stop in chunks(start + 1, end - 1):
            if first + 2 < stop and tokens[first].kind in {"identifier", "string"} and tokens[first + 1].value == ":":
                if tokens[first].value in result:
                    errors.append("Duplicate JavaScript tool metadata property at line %s; interpretation is ambiguous." % (text.count("\n", 0, tokens[first].start) + 1))
                result[tokens[first].value] = (first + 2, stop)
            elif tokens[first].value == "description" or tokens[first].value in {".", "...", "["}:
                errors.append("Computed, shorthand or spread JavaScript tool metadata at line %s requires contextual review." % (text.count("\n", 0, tokens[first].start) + 1))
        return result
    def string(first, stop):
        if first >= stop or stop - first > 41 or (stop - first) % 2 != 1:
            return None
        result = []
        for i in range(first, stop):
            token = tokens[i]
            if (i - first) % 2:
                if token.value != "+" or token.kind != "punctuation":
                    return None
            elif token.kind == "string" or (token.kind == "template" and not token.children):
                result.append(token.value)
            else:
                return None
        return "".join(result)
    segments = []
    for i, token in enumerate(tokens):
        if token.kind != "identifier" or token.value not in {"registerTool", "tool"} or i + 1 not in pairs or tokens[i + 1].value != "(":
            continue
        args = chunks(i + 2, pairs[i + 1])
        if len(args) < 2:
            continue
        metadata = props(*args[1])
        readonly = False
        desc = metadata.get("description")
        if "annotations" in metadata:
            annotation = props(*metadata["annotations"]).get("readOnlyHint")
            readonly = bool(annotation and annotation[1] - annotation[0] == 1 and tokens[annotation[0]].kind == "identifier" and tokens[annotation[0]].value == "true")
        if desc is None and token.value == "tool" and string(*args[1]) is not None:
            desc = args[1]
        if desc:
            value = string(*desc)
            line = text.count("\n", 0, tokens[desc[0]].start) + 1
            if value is None:
                errors.append("Dynamic JavaScript tool description at line %s was not resolved; instruction-threat checks require literal metadata." % line)
            else:
                segments.append(Segment(value, line, "JavaScript literal tool description", readonly))
    return segments


def inspect_instructions(path, text, tokenize=None, instruction_context=False):
    """Return (rule/line/confidence/detail tuples, coverage errors, shell blocks).

    The optional instruction_context is for caller-discovered skill references.
    Bounds are reported, never silently treated as a clean inspection.
    """
    suffix = PurePosixPath(path).suffix.lower()
    markdown = is_instruction_path(path) or instruction_context
    if not markdown and suffix not in {".py", ".pyi", ".json", ".jsonc"} | _JS:
        return [], [], []
    errors, records, shell = [], [], []
    document_limit = MAX_DOCUMENT if markdown else MAX_METADATA_DOCUMENT
    if len(text) > document_limit:
        errors.append("Instruction-threat inspection is bounded to %s characters for %s; remaining instruction/tool metadata needs review." % (document_limit, "instruction documents" if markdown else "source metadata"))
        text = text[:document_limit]
    front_end = 0
    if markdown:
        segments, shell, front_end = _markdown(text, errors)
        for body, line in shell:
            records.extend(_shell_pipeline_records(body, line, errors))
        if front_end:
            for number, line in enumerate(text.splitlines()[:front_end], 1):
                match = re.match(r"^allowed-tools\s*:\s*(.*?)\s*$", line)
                if match:
                    value = match.group(1)
                    quoted = re.fullmatch(r"(['\"])(.*?)\1\s*(?:#.*)?", value)
                    value = quoted.group(2) if quoted else value.split(" #", 1)[0].strip()
                    if any(re.fullmatch(r"\*|(?:Bash|Shell|Execute)\(\*\)", item, re.I) for item in value.split()):
                        records.append(("AI027", number, "medium", "Skill frontmatter explicitly preapproves every tool or an unrestricted shell. Runtime interpretation of this experimental field varies by client."))
                    elif not value or value.startswith(("*", "&", "!", "|", ">", "[", "{")):
                        errors.append("Skill allowed-tools uses a nonliteral/complex value at line %s; its effective grant needs review." % number)
    elif suffix in {".py", ".pyi"}:
        segments = _python_segments(text, errors)
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            pass  # The ordinary Python analyzer retains syntax failures.
        else:
            from .tool_effects import inspect_python_tool_effects
            effect_records, effect_errors = inspect_python_tool_effects(tree)
            records.extend(effect_records)
            errors.extend(effect_errors)
    elif suffix in {".json", ".jsonc"}:
        segments = _json_segments(text, errors)
    else:
        segments = _js_segments(text, tokenize, errors)
    if len(segments) > MAX_SEGMENTS:
        errors.append("Instruction-threat inspection exceeded 2048 text segments; remaining segments need review.")
        segments = segments[:MAX_SEGMENTS]
    encodings = 0
    for segment in segments:
        if len(segment.text) > MAX_SEGMENT:
            errors.append("Instruction/tool text at line %s exceeds 8192 characters; remaining text needs review." % segment.line)
        segment = Segment(segment.text, segment.line + segment.text.count("\n", 0, len(segment.text) - len(segment.text.lstrip())), segment.surface, segment.read_only)
        value = _normalize(segment.text[:MAX_SEGMENT])
        detail = " Normalized Unicode/HTML formatting before matching." if value != segment.text[:MAX_SEGMENT].strip() else ""
        records.extend(_predicate_records(segment, value, detail))
        if _educational(value):
            continue
        for match in _BASE64.finditer(value):
            prefix = value[max(0, match.start() - 80):match.start()]
            if re.search(r"\b(?:do not|don't|never|must not)\s+(?:(?:execute|decode|follow|run|obey)\s+)?(?:this\s+)?$", prefix, re.I):
                continue
            encodings += 1
            if encodings > MAX_ENCODINGS:
                if encodings == MAX_ENCODINGS + 1:
                    errors.append("Instruction analysis exceeded 32 labelled base64 values; remaining encoded content needs review.")
                continue
            raw = match.group(1)
            if len(raw) > MAX_DECODED * 4 // 3 + 4:
                errors.append("A labelled base64 instruction exceeds the 8192-byte decoded limit; encoded content needs review.")
                continue
            try:
                decoded = base64.b64decode(raw, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeError, ValueError):
                errors.append("A labelled base64 instruction could not be decoded as bounded UTF-8; encoded content needs review.")
                continue
            decoded_segment = Segment(decoded, segment.line + value.count("\n", 0, match.start()), segment.surface, segment.read_only)
            found = _predicate_records(decoded_segment, _normalize(decoded), " Matched one explicitly labelled base64 layer; original encoded evidence is retained.")
            # Decoded newlines are not source lines. Anchor every match to its
            # original encoded value so the evidence remains source-verifiable.
            records.extend((rule, decoded_segment.line, confidence, detail) for rule, _, confidence, detail in found)
            if _BASE64.search(decoded):
                errors.append("Nested base64 instructions were not recursively decoded; further encoded content needs review.")
    return records, sorted(set(errors)), shell
