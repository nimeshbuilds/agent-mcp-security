"""Literal local skill reference discovery over already-read bounded files.

This is a bounded Markdown-link subset, not a Markdown interpreter. No files are
read, URLs fetched, symlinks followed, or target commands interpreted. References
outside a skill's directory and unscanned local references remain visible gaps.
"""
import posixpath
import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

MAX_REFERENCES = 2048
_ESCAPED = re.compile(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])")
_INLINE = re.compile(r'\]\(')
_DEFINITION = re.compile(r'^ {0,3}\[((?:\\.|[^\]\\\n]){1,512})\]:[ \t]*(.*)$', re.M)
_LABEL = re.compile(r'\[((?:\\.|[^\]\\\n]){1,512})\](?:\[((?:\\.|[^\]\\\n]){0,512})\])?')
_BACKTICK = re.compile(r'`([^`\n]+\.(?:md|mdc)(?:#[^`\n]*)?)`', re.I)
_HTML_REF = re.compile(r'\b(?:href|src)\s*=\s*([\"\'])(.*?)\1', re.I)


def _unescape(value):
    return _ESCAPED.sub(lambda match: match.group(1), value)


def _label(value):
    return ' '.join(_unescape(value).split()).casefold()


def _markdown_like(value):
    return bool(re.search(r'\.(?:md|mdc)(?:[^A-Za-z0-9_]|$)', value, re.I))


def _destination(value, inline=False):
    """Read a literal destination and optional title, with bounded nesting."""
    leading = value[:len(value) - len(value.lstrip(' \t\r\n'))]
    if leading.count('\n') > 1:
        return None
    value = value.lstrip(' \t\r\n')
    if not value:
        return None
    out, i, depth = [], 0, 0
    if value.startswith('<'):
        i = 1
        while i < len(value):
            char = value[i]
            if char == '\\' and i + 1 < len(value):
                out.append(value[i:i + 2]); i += 2; continue
            if char == '>':
                i += 1
                break
            if char in '\r\n<' or ord(char) < 32:
                return None
            out.append(char); i += 1
        else:
            return None
    else:
        while i < len(value):
            char = value[i]
            if char == '\\' and i + 1 < len(value):
                out.append(value[i:i + 2]); i += 2; continue
            if char == '(':
                depth += 1
                if depth > 32:
                    return None
            elif char == ')':
                if depth == 0:
                    break
                depth -= 1
            elif char.isspace() or char in '<>':
                break
            out.append(char); i += 1
        if depth:
            return None
    if not out:
        return None
    # The destination is followed by a closing ')' or an optional literal title.
    tail = value[i:].strip()
    if inline:
        valid_tail = bool(re.match(r'^(?:\)|(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\([^()]*\))[ \t]*\))', tail))
    else:
        valid_tail = not tail or bool(re.fullmatch(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\([^()]*\)', tail))
    return _unescape(''.join(out)) if valid_tail else None


def _references(text):
    references, problems, definitions, definition_spans = [], [], {}, []
    syntax_left = MAX_REFERENCES * 4
    def charge():
        nonlocal syntax_left
        syntax_left -= 1
        if syntax_left < 0:
            if syntax_left == -1:
                problems.append('Skill reference-syntax budget exhausted; additional local references remain unclassified')
            return False
        return True
    for match in _DEFINITION.finditer(text):
        if not charge():
            break
        definition_spans.append((match.start(), match.end()))
        if len(definition_spans) > MAX_REFERENCES:
            problems.append('Skill reference-definition budget exhausted; additional reference syntax remains unclassified')
            break
        raw_destination = match.group(2)
        if not raw_destination.strip():
            following = text[match.end():match.end() + 4096]
            raw_destination = following.lstrip('\r\n').split('\n', 1)[0] if following.startswith(('\n', '\r\n')) else ''
        destination = _destination(raw_destination)
        key = _label(match.group(1))
        if destination is None:
            if _markdown_like(raw_destination):
                problems.append('Unsupported local Markdown reference definition requires review: ' + raw_destination[:500])
            continue
        # CommonMark keeps the first definition for a normalized label.
        definitions.setdefault(key, destination)
    def add(reference):
        if len(references) <= MAX_REFERENCES:
            references.append(reference)
    for match in _INLINE.finditer(text):
        if not charge():
            break
        line = text[match.end():match.end() + 4096]
        destination = _destination(line, inline=True)
        if destination is not None:
            add(destination)
        elif _markdown_like(line):
            problems.append('Unsupported apparent local Markdown link requires review: ' + line[:500])
    for match in _LABEL.finditer(text):
        if not charge():
            break
        if any(start <= match.start() < end for start, end in definition_spans):
            continue
        if text[match.end():match.end() + 1] == '(':
            continue  # Inline destination already handled above.
        key = _label(match.group(2) or match.group(1))
        if key in definitions:
            add(definitions[key])
        elif match.group(2) is not None and _markdown_like(key):
            problems.append('Unresolved local Markdown reference label requires review: ' + key[:500])
    for match in _BACKTICK.finditer(text):
        if not charge():
            break
        add(_unescape(match.group(1)))
    for match in _HTML_REF.finditer(text):
        if not charge():
            break
        try:
            remote = bool(urlsplit(match.group(2)).scheme or urlsplit(match.group(2)).netloc)
        except ValueError:
            remote = False
        if _markdown_like(match.group(2)) and not remote:
            problems.append('HTML Markdown references are outside literal-link discovery and require review: ' + match.group(2)[:500])
    return references, problems


def discover_skill_scope(documents):
    contextual, roots, errors = set(), [], []
    remaining = MAX_REFERENCES
    for root_file in sorted(p for p in documents if PurePosixPath(p).name.lower() == 'skill.md'):
        root = posixpath.dirname(root_file)
        roots.append(root_file)
        queue, visited = [root_file], set()
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            contextual.add(current)
            references, problems = _references(documents[current])
            errors.extend({'path': current, 'kind': 'skill_reference_unresolved', 'error': problem} for problem in problems)
            for reference in references:
                if remaining <= 0:
                    errors.append({'path': current, 'kind': 'skill_reference_limit', 'error': 'Skill local-reference budget exhausted; additional references remain unclassified'})
                    return contextual, roots, errors
                remaining -= 1
                try:
                    parsed = urlsplit(reference)
                except ValueError:
                    if _markdown_like(reference):
                        errors.append({'path': current, 'kind': 'skill_reference_unresolved', 'error': 'Malformed skill Markdown reference requires review: ' + reference[:500]})
                    continue
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                decoded = unquote(parsed.path)
                if PurePosixPath(decoded).suffix.lower() not in {'.md', '.mdc'}:
                    continue
                target = posixpath.normpath(posixpath.join(posixpath.dirname(current), decoded))
                confined = not decoded.startswith('/') and '\\' not in decoded and target != '..' and not target.startswith('../') and (not root or target.startswith(root + '/'))
                if not confined or target not in documents:
                    errors.append({'path': current, 'kind': 'skill_reference_unresolved', 'error': 'Literal skill Markdown reference was not inspected within the skill directory: ' + reference[:500]})
                    continue
                if target not in visited:
                    queue.append(target)
    unique = {(item['path'], item['error']): item for item in errors}
    return contextual, roots, [unique[key] for key in sorted(unique)]
