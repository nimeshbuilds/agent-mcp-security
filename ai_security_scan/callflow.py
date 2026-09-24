"""Bounded, literal wrapper summaries for the tokenized JavaScript profile.

This module does not parse all JS/TS. A summary requires a top-level function
whose complete body is a direct returned call, with simple parameters. It binds
actual external arguments at a call site and emits at the eventual HTTP sink.
Unrecognized bodies never become a fabricated summary or a safety proof.
"""


def javascript_wrappers(tokens, pairs):
    """Return immutable-shape summaries keyed by the declaration token offset."""
    summaries, depth, index = {}, 0, 0
    count = len(tokens)

    def value(index):
        return tokens[index].value if 0 <= index < count else ""

    def parameters(start, end):
        result, cursor = [], start
        while cursor < end:
            if tokens[cursor].kind != "identifier":
                return None
            result.append(value(cursor))
            cursor += 1
            # Narrow TypeScript annotation: no defaults, destructuring,
            # function types, optional/rest parameters or generic arguments.
            if value(cursor) == ":":
                cursor += 1
                if cursor >= end or tokens[cursor].kind != "identifier":
                    return None
                cursor += 1
                while value(cursor) == "[" and value(cursor + 1) == "]":
                    cursor += 2
            if cursor < end:
                if value(cursor) != ",":
                    return None
                cursor += 1
        return result if len(result) == len(set(result)) and len(result) <= 32 else None

    while index < count:
        word = value(index)
        if depth == 0 and word in {"const", "let", "var"} and tokens[index + 1:index + 2] and tokens[index + 1].kind == "identifier" and value(index + 2) == "=":
            start = index + 3
            if value(start) == "async":
                start += 1
            closing = pairs.get(start) if value(start) == "(" else start
            arrow = closing + 1 if closing is not None else count
            params = parameters(start + 1, closing) if value(start) == "(" and closing is not None else parameters(start, start + 1)
            if params is not None and value(arrow) == "=>":
                body_start = arrow + 1
                if value(body_start) == "{":
                    body_end = pairs.get(body_start)
                    body = tokens[body_start + 1:body_end] if body_end is not None else []
                    if body and body[-1].value == ";":
                        body = body[:-1]
                    body = body[1:] if body and body[0].value == "return" else []
                else:
                    body_end = body_start
                    while body_end < count and value(body_end) not in {";", ","}:
                        if value(body_end) in {"const", "let", "var", "function", "import"}:
                            break
                        if body_end in pairs and value(body_end) in {"(", "[", "{"}:
                            body_end = pairs[body_end]
                        body_end += 1
                    body = tokens[body_start:body_end]
                if body and body[0].value == "await":
                    body = body[1:]
                if body:
                    summaries[index] = {"name": value(index + 1), "parameters": params,
                                        "body": body, "start": index, "end": body_end, "arrow": True}
        if depth == 0 and word == "function" and tokens[index + 1:index + 2] and tokens[index + 1].kind == "identifier" and value(index + 2) == "(":
            opening = index + 2
            closing = pairs.get(opening)
            body_start = closing + 1 if closing is not None else count
            if value(body_start) == ":" and tokens[body_start + 1:body_start + 2] and tokens[body_start + 1].kind == "identifier":
                body_start += 2
            body_end = pairs.get(body_start) if value(body_start) == "{" else None
            if body_end is not None:
                params = parameters(opening + 1, closing)
                body = tokens[body_start + 1:body_end]
                if body and body[-1].value == ";":
                    body = body[:-1]
                if body and body[0].value == "return":
                    body = body[1:]
                    if body and body[0].value == "await":
                        body = body[1:]
                else:
                    body = []
                if params is not None and body:
                    summaries[index] = {"name": value(index + 1), "parameters": params,
                                        "body": body, "start": index, "end": body_end}
        if word == "{":
            depth += 1
        elif word == "}":
            depth = max(0, depth - 1)
        index += 1
    return summaries


def resolve_javascript_wrappers(summaries, pairs_function):
    """Resolve direct wrapper chains; cap both chain depth and summary work."""
    by_name = {}
    for index, summary in summaries.items():
        by_name.setdefault(summary["name"], []).append(index)
    results, unresolved = {}, {}
    work = [0]

    def resolve(index, stack):
        work[0] += 1
        if work[0] > 8192:
            raise ValueError("JavaScript wrapper summary work budget exceeded; coverage is incomplete")
        if index in results:
            return results[index]
        if index in stack or len(stack) >= 8:
            unresolved[index] = "JavaScript wrapper recursion/depth limit reached; interprocedural coverage is incomplete"
            return None
        summary = summaries[index]
        body = summary["body"]
        words = [item.value for item in body]
        pairs = pairs_function(body)
        opening = 1 if len(body) > 1 and words[1] == "(" else 3 if len(body) > 3 and words[1] in {".", "?."} and words[3] == "(" else None
        if opening is None or pairs.get(opening) != len(body) - 1:
            return None
        name = "".join(words[:opening])
        args, start, cursor = [], opening + 1, opening + 1
        while cursor < len(body) - 1:
            if words[cursor] == ",":
                args.append(body[start:cursor])
                start = cursor + 1
            elif cursor in pairs and words[cursor] in {"(", "[", "{"}:
                cursor = pairs[cursor]
            cursor += 1
        if start < len(body) - 1:
            args.append(body[start:len(body) - 1])
        if not args:
            return None
        if name in {"fetch", "axios.get", "axios.post", "axios.put", "axios.patch", "axios.delete", "axios.head", "axios.options"}:
            # A same-named parameter shadows these bindings. A module-level
            # import/reassignment is checked by the caller at the use site.
            if words[0] in summary["parameters"]:
                return None
            result = {"input": args[0], "sink": body[0], "sink_end": body[-1], "rule": "AI014",
                      "chain": [summary["name"]], "sink_binding": words[0],
                      "bindings": []}
        elif name in by_name and len(by_name[name]) == 1 and name not in summary["parameters"]:
            nested_index = by_name[name][0]
            nested = resolve(nested_index, stack + [index])
            if nested is None:
                if nested_index in unresolved:
                    unresolved[index] = unresolved[nested_index]
                return None
            parameters = summaries[nested_index]["parameters"]
            # Map each dependency separately; avoid pretending parameter
            # substitution validates arbitrary JavaScript expressions.
            dependencies = {item.value for item in nested["input"] if item.kind == "identifier" and item.value in parameters}
            selected = [token for offset, param in enumerate(parameters) if param in dependencies and offset < len(args) for token in args[offset]]
            result = dict(nested, input=selected, chain=[summary["name"]] + nested["chain"], bindings=[nested_index] + nested["bindings"])
        elif opening == 1 and words[0] not in summary["parameters"]:
            # Only an actual filesystem import binding at the use site makes
            # this a sink. Arbitrary same-spelled user functions do not qualify.
            result = {"input": args[0], "sink": body[0], "sink_end": body[-1], "rule": "AI015",
                      "chain": [summary["name"]], "sink_binding": words[0], "bindings": [],
                      "requires_filesystem_import": True}
        elif opening == 3 and words[2] in {"readFile", "readFileSync", "writeFile", "writeFileSync", "unlink", "rm"} and words[0] not in summary["parameters"]:
            result = {"input": args[0], "sink": body[0], "sink_end": body[-1], "rule": "AI015",
                      "chain": [summary["name"]], "sink_binding": words[0], "bindings": [],
                      "requires_filesystem_import": True}
        else:
            return None
        results[index] = result
        return result

    for index in summaries:
        resolve(index, [])
    return results, unresolved


def javascript_tool_inputs(tokens, pairs):
    """Recognize inline registerTool callbacks; return arrow-offset input names.

    The receiver must be conventionally named server/mcp, the name literal and
    configuration must contain inputSchema. Simple first-parameter objects may
    rename fields. Rest/default/computed/nested bindings remain explicit gaps.
    """
    result, gaps = {}, []
    for index, token in enumerate(tokens):
        if token.value != "registerTool" or index < 2 or tokens[index - 1].value != "." or tokens[index - 2].value not in {"server", "mcp"}:
            continue
        opening = index + 1
        if opening not in pairs or tokens[opening].value != "(":
            continue
        closing = pairs[opening]
        args, start, cursor = [], opening + 1, opening + 1
        while cursor < closing:
            if tokens[cursor].value == ",":
                args.append((start, cursor))
                start = cursor + 1
            elif cursor in pairs and tokens[cursor].value in {"(", "[", "{"}:
                cursor = pairs[cursor]
            cursor += 1
        if start < closing:
            args.append((start, closing))
        if len(args) != 3 or args[0][1] - args[0][0] != 1 or tokens[args[0][0]].kind != "string":
            continue
        config_start, config_end = args[1]
        if tokens[config_start].value != "{" or not any(item.value == "inputSchema" for item in tokens[config_start:config_end]):
            continue
        first, stop = args[2]
        if stop - first == 1 and tokens[first].kind == "identifier":
            # A referenced handler is outside this explicitly inline-callback
            # profile; its literal metadata still receives ordinary checks.
            continue
        if tokens[first].value == "async":
            first += 1
        end = pairs.get(first)
        if tokens[first].value != "(" or end is None or end + 1 >= stop or tokens[end + 1].value != "=>":
            gaps.append("MCP registerTool callback parameters require unsupported binding analysis; tool entrypoint coverage is incomplete")
            continue
        parameter = tokens[first + 1:end]
        names = []
        if len(parameter) == 1 and parameter[0].kind == "identifier":
            names = [parameter[0].value]
        elif len(parameter) >= 3 and parameter[0].value == "{" and parameter[-1].value == "}":
            cursor = 1
            while cursor < len(parameter) - 1:
                if parameter[cursor].kind != "identifier":
                    names = []
                    break
                name = parameter[cursor].value
                cursor += 1
                if parameter[cursor].value == ":":
                    cursor += 1
                    if parameter[cursor].kind != "identifier":
                        names = []
                        break
                    name = parameter[cursor].value
                    cursor += 1
                names.append(name)
                if cursor < len(parameter) - 1:
                    if parameter[cursor].value != ",":
                        names = []
                        break
                    cursor += 1
        if not parameter or len(parameter) == 2 and parameter[0].value == "{" and parameter[1].value == "}":
            names = []  # A zero-input tool has no parameter taint to seed.
        elif not names or len(names) > 32:
            gaps.append("MCP registerTool callback uses complex/default/rest parameters; tool entrypoint coverage is incomplete")
            continue
        result[tokens[end + 1].start] = {"names": set(names), "receiver": tokens[index - 2].value}
    return result, gaps
