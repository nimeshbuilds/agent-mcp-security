"""Conservative write-effect witnesses for explicitly read-only Python tools.

This is a same-function syntactic contract check, not an execution prediction.
Only recognized imported APIs with unambiguous bindings produce witnesses.
Unknown helpers, mutation through aliases and runtime registration need review.
"""
import ast

MAX_EFFECT_NODES = 20000
_WRITES = {
    'os.remove', 'os.unlink', 'os.rmdir', 'os.rename', 'os.replace', 'os.mkdir',
    'os.makedirs', 'os.chmod', 'shutil.rmtree', 'shutil.move', 'shutil.copy',
    'shutil.copy2', 'shutil.copyfile',
}
_PATH_WRITES = {'write_text', 'write_bytes', 'unlink', 'rmdir', 'rename',
                'replace', 'mkdir', 'touch', 'chmod'}


def _walk_scope(nodes):
    """Walk live statement prefixes and definition-time expressions only."""
    def live_sequence(values):
        live = []
        for value in values:
            live.append(value)
            if isinstance(value, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                break
        return live
    pending = list(reversed(live_sequence(nodes)))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, ast.If):
            if isinstance(node.test, ast.Constant):
                children = live_sequence(node.body if node.test.value else node.orelse)
            else:
                children = [node.test] + live_sequence(node.body) + live_sequence(node.orelse)
            pending.extend(reversed(children))
        elif isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and not node.test.value:
            pending.extend(reversed(live_sequence(node.orelse)))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # Function bodies are deferred; decorators/default expressions run
            # in the enclosing scope when the definition is evaluated.
            children = list(getattr(node, 'decorator_list', [])) + list(node.args.defaults)
            children += [value for value in node.args.kw_defaults if value is not None]
            pending.extend(reversed(children))
        elif isinstance(node, ast.ClassDef):
            pending.extend(reversed(node.decorator_list + node.bases + [item.value for item in node.keywords]))
        else:
            children = []
            for _, value in ast.iter_fields(node):
                if isinstance(value, list):
                    children.extend(live_sequence(value) if value and isinstance(value[0], ast.stmt)
                                    else [item for item in value if isinstance(item, ast.AST)])
                elif isinstance(value, ast.AST):
                    children.append(value)
            pending.extend(reversed(children))


def _imports(nodes):
    aliases, blocked = {}, set()
    direct = set(nodes)
    def bind(name, value):
        if name in aliases and aliases[name] != value:
            blocked.add(name)
        aliases[name] = value
    for node in _walk_scope(nodes):
        if isinstance(node, ast.Import):
            for value in node.names:
                bind(value.asname or value.name.split('.')[0], value.name if value.asname else value.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            for value in node.names:
                if value.name != '*':
                    bind(value.asname or value.name, ('.' * node.level) + (node.module or '') + '.' + value.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            blocked.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            blocked.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            blocked.add(node.name)
        elif type(node).__name__ in {'MatchAs', 'MatchStar'} and getattr(node, 'name', None):
            blocked.add(node.name)
        elif type(node).__name__ == 'MatchMapping' and getattr(node, 'rest', None):
            blocked.add(node.rest)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            value = node
            while isinstance(value, ast.Attribute):
                value = value.value
            if isinstance(value, ast.Name):
                blocked.add(value.id)
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in direct:
            blocked.update(value.asname or value.name.split('.')[0] for value in node.names)
    return {key: value for key, value in aliases.items() if key not in blocked}, blocked


def _name(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, '')
    if isinstance(node, ast.Attribute):
        base = _name(node.value, aliases)
        return base + '.' + node.attr if base else ''
    return ''


def _readonly(fn):
    for decorator in fn.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        target = decorator.func
        name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ''
        if name != 'tool' or any(kw.arg is None for kw in decorator.keywords):
            continue
        annotation = next((kw.value for kw in decorator.keywords if kw.arg == 'annotations'), None)
        value = None
        if isinstance(annotation, ast.Dict):
            keys = [key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None for key in annotation.keys]
            if None in keys:
                continue
            value = dict(zip(keys, annotation.values)).get('readOnlyHint')
        elif isinstance(annotation, ast.Call):
            target = annotation.func
            name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ''
            keys = [kw.arg for kw in annotation.keywords]
            if name == 'ToolAnnotations' and None not in keys and len(keys) == len(set(keys)):
                value = next((kw.value for kw in annotation.keywords if kw.arg == 'readOnlyHint'), None)
        if isinstance(value, ast.Constant) and value.value is True:
            return True
    return False


def inspect_python_tool_effects(tree):
    records, errors = [], []
    globals_, _ = _imports(tree.body)
    consumed = 0
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or not _readonly(fn):
            continue
        # Nested closures/classes have resolution rules this checker does not
        # model. Restrict witnesses to top-level tool handlers.
        if fn not in tree.body:
            errors.append('Read-only tool effect analysis at line %s cannot resolve nested/class bindings; handler effects need review.' % fn.lineno)
            continue
        local, blocked = _imports(fn.body)
        local_import_lines = {}
        for statement in fn.body:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                for value in statement.names:
                    binding = value.asname or (value.name.split('.')[0] if isinstance(statement, ast.Import) else value.name)
                    local_import_lines.setdefault(binding, (statement.lineno, statement.col_offset))
        params = {arg.arg for arg in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs}
        params.update(arg.arg for arg in (fn.args.vararg, fn.args.kwarg) if arg)
        aliases = {key: value for key, value in globals_.items() if key not in blocked | params}
        aliases.update({key: value for key, value in local.items() if key not in params})
        for node in _walk_scope(fn.body):
            consumed += 1
            if consumed > MAX_EFFECT_NODES:
                errors.append('Read-only tool write-effect analysis exceeded 20000 AST nodes; remaining handler effects need review.')
                return records, errors
            if not isinstance(node, ast.Call):
                if isinstance(node, ast.ClassDef):
                    errors.append('Read-only tool effect analysis at line %s does not resolve nested class-body execution or class-local bindings; those effects need review.' % node.lineno)
                continue
            available = {key: value for key, value in aliases.items()
                         if key not in local_import_lines or local_import_lines[key] <= (node.lineno, node.col_offset)}
            api = _name(node.func, available)
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
                if _name(node.func.value.func, available) == 'pathlib.Path' and node.func.attr in _PATH_WRITES:
                    api = 'pathlib.Path.' + node.func.attr
            if api not in _WRITES and api not in {'pathlib.Path.' + method for method in _PATH_WRITES}:
                continue
            records.append(('AI046', node.lineno, 'high',
                            'Python tool %s declares readOnlyHint=true at line %s but contains a statically resolved %s write operation. This is a code/annotation contract conflict; branch reachability, actual execution and authorization remain unverified.' % (fn.name, fn.lineno, api)))
    return records, errors
