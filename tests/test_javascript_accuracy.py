"""Independent JS/TS accuracy regression and metamorphic cases.

These assert bounded lexical semantics, not whole-program vulnerability proofs.
Cases do not require a JavaScript runtime or execute the analyzed source.
"""
import json
import unittest

from ai_security_scan.analyzer import analyze_file


def rules(source, path="agent.js"):
    return {finding["rule_id"] for finding in analyze_file(path, source)}


class JavaScriptAccuracyTests(unittest.TestCase):
    def test_executable_rules_ignore_inert_code_strings(self):
        payloads = [
            "eval(userInput)", "new Function(userInput)",
            "import {exec} from 'child_process'; exec(userInput)",
            "rejectUnauthorized: false", "origin: '*'", "host: '0.0.0.0'",
            "algorithms: ['none']", "auth: false", "tokenPassthrough: true",
            "dangerouslyAllowBrowser: true", "bypassPermissions: true",
            "allowedTools: ['*']", "fetch(req.body.url)",
            "fs.readFileSync(req.query.path)",
            "{role: 'system', content: toolOutput}",
            "console.log(apiKey)", "element.innerHTML = toolOutput",
        ]
        for payload in payloads:
            for quote in (json.dumps(payload), "`" + payload + "`"):
                with self.subTest(payload=payload, quote=quote[0]):
                    self.assertEqual(set(), rules("const documentation = " + quote + ";"))

    def test_fake_module_import_never_creates_alias(self):
        sources = [
            'const docs = "import {exec} from \'child_process\'"; exec(userInput);',
            'const docs = "const cp = require(\'child_process\')"; cp.exec(userInput);',
            "/* import {exec} from 'child_process' */ exec(userInput);",
            "// import {exec} from 'child_process'\nexec(userInput);",
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertNotIn("AI012", rules(source))

    def test_regex_bodies_are_inert_in_operand_and_control_positions(self):
        sources = [
            r"const pattern = /eval(userInput); rejectUnauthorized: false/;",
            r"return /eval(userInput)/;",
            r"if (enabled) /eval(userInput)/.test(text);",
            r"while (enabled) /eval(userInput)/.test(text);",
            r"const pattern = /[/]eval\(userInput\)/gi;",
            r"const pattern = /[\/]eval(userInput)/;",
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertNotIn("AI013", rules(source))
                self.assertNotIn("AI006", rules(source))

    def test_division_does_not_hide_following_executable_code(self):
        self.assertIn("AI013", rules("const ratio = size / count; eval(userInput);"))
        self.assertIn("AI013", rules("const ratio = size / eval(userInput) / count;"))

    def test_dynamic_eval_literal_prefix_and_wrapping(self):
        unsafe = [
            "eval('prefix' + userInput);", "eval((userInput));",
            "eval(\n'prefix' +\nuserInput\n);", "eval?.(userInput);",
            "eval(`prefix ${userInput}`);", "eval(`prefix ${`${userInput}`}`);",
        ]
        safe = [
            "eval('fixed');", "eval(('fixed'));", "eval('a' + 'b');",
            "eval(`fixed`);", r"eval(`literal \${userInput}`);",
            "eval(`fixed ${'literal'}`);", "eval(42);",
        ]
        for source in unsafe:
            with self.subTest(source=source): self.assertIn("AI013", rules(source))
        for source in safe:
            with self.subTest(source=source): self.assertNotIn("AI013", rules(source))

    def test_function_constructor_checks_every_argument(self):
        unsafe = [
            "new Function('argument', toolOutput);",
            "Function('first', 'second', 'return ' + toolOutput);",
            "new Function(userInput, 'return fixed');",
            "new Function(\n'x',\n`return ${userInput}`\n);",
        ]
        for source in unsafe:
            with self.subTest(source=source): self.assertIn("AI013", rules(source))
        for source in ["new Function('x', 'return x');", "Function('x', `return x`);", "new Function();"]:
            with self.subTest(source=source): self.assertNotIn("AI013", rules(source))

    def test_direct_code_execution_aliases(self):
        for source in [
            "const evaluate = eval; evaluate(userInput);",
            "const Compile = Function; new Compile('x', userInput);",
            "const a = eval; const b = a; b(userInput);",
        ]:
            with self.subTest(source=source): self.assertIn("AI013", rules(source))
        self.assertNotIn("AI013", rules("const evaluate = safeEval; evaluate(userInput);"))

    def test_shell_member_aliases_and_require_forms(self):
        sources = [
            "import {exec} from 'child_process'; const run = exec; run(userInput);",
            "import * as cp from 'node:child_process'; const run = cp.execSync; run(userInput);",
            "const cp = require('child_process'); const {exec: run} = cp; run(userInput);",
            "require('node:child_process').exec(userInput);",
            "const cp = require('child_process'); cp['exec'](userInput);",
            "const cp = require('child_process'); cp?.exec?.(userInput);",
            "const cp = require('child_process'); const run = cp['execSync']; run(userInput);",
        ]
        for source in sources:
            with self.subTest(source=source): self.assertIn("AI012", rules(source))

    def test_execfile_does_not_become_shell_alias(self):
        for source in [
            "import {execFile as run} from 'child_process'; run(userInput);",
            "const cp = require('child_process'); const run = cp.execFile; run(userInput);",
            "const cp = require('child_process'); cp.spawn('tool', [userInput]);",
            "import {exec} from 'child_process'; object.exec(userInput);",
            "import {exec} from 'unrelated'; exec(userInput);",
        ]:
            with self.subTest(source=source): self.assertNotIn("AI012", rules(source))

    def test_escaped_module_and_member_literals(self):
        self.assertIn("AI012", rules(r"const cp = require('child\x5fprocess'); cp['\u0065xec'](userInput);"))
        self.assertIn("AI007", rules(r"const cfg = {'origin': '\x2a'};"))

    def test_alias_reassignment_and_shadowing(self):
        safe = [
            "import {exec} from 'child_process'; exec = safe; exec(userInput);",
            "import {exec} from 'child_process'; function task(exec) { exec(userInput); }",
            "import {exec} from 'child_process'; const task = (exec) => { exec(userInput); };",
            "import {exec} from 'child_process'; const task = exec => { exec(userInput); };",
            "function eval(value) { return value; } eval(userInput);",
            "const eval = safe; eval(userInput);",
            "import {eval} from 'safe-helpers'; eval(userInput);",
            "import Function from 'safe-helpers'; new Function(userInput);",
            "const {eval} = safeHelpers; eval(userInput);",
            "const task = eval => eval(userInput);",
            "const task = (eval) => eval(userInput);",
            "import {exec} from 'child_process'; const task = exec => exec(userInput);",
            "import {exec} from 'child_process'; { const exec = safe; exec(userInput); }",
        ]
        for source in safe:
            with self.subTest(source=source):
                self.assertFalse({"AI012", "AI013"} & rules(source))
        self.assertIn("AI013", rules("const task = eval => eval(userInput); eval(userInput);"))
        self.assertIn("AI013", rules("const task = value => eval(value);"))
        source = "import {exec} from 'child_process';\nfunction task(exec) { exec(userInput); }\nexec(userInput);"
        findings = [finding for finding in analyze_file("a.js", source) if finding["rule_id"] == "AI012"]
        self.assertEqual([3], [finding["line"] for finding in findings])

    def test_nested_template_expression_is_executable(self):
        for source in [
            "const x = `prefix ${eval(userInput)}`;",
            "const x = `prefix ${`nested ${eval(userInput)}`}`;",
            "const x = `${({value: eval(userInput)}).value}`;",
            "const x = `${/* ignored eval('fixed') */ eval(userInput)}`;",
        ]:
            with self.subTest(source=source): self.assertIn("AI013", rules(source))
        self.assertNotIn("AI013", rules('const x = `prefix ${"eval(userInput)"}`;'))

    def test_config_quoted_keys_multiline_and_array_position(self):
        cases = [
            ("AI006", "const cfg = {'rejectUnauthorized':\nfalse};"),
            ("AI007", "const cfg = {origin: ['https://example.com', '*']};"),
            ("AI017", "const cfg = {algorithms: ['RS256', 'none']};"),
            ("AI027", "const cfg = {allowedTools: ['safe_tool', '*']};"),
            ("AI031", "const cfg = {autoApprove: ['safe_tool', '*']};"),
            ("AI006", "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';"),
        ]
        for rule, source in cases:
            with self.subTest(rule=rule): self.assertIn(rule, rules(source))

    def test_string_boolean_config_is_not_actual_boolean(self):
        source = "const cfg = {auth: 'false', rejectUnauthorized: 'false', tokenPassthrough: 'true', dangerouslyAllowBrowser: 'true', autoApproveAll: 'true'};"
        self.assertFalse({"AI006", "AI026", "AI028", "AI030", "AI031"} & rules(source))

    def test_source_expressions_can_span_lines_and_wrappers(self):
        cases = [
            ("AI014", "fetch(\n new URL(req.body.url)\n);"),
            ("AI014", "fetch('https://' + userInput);"),
            ("AI014", "axios.get(`https://${req.query.host}/`);"),
            ("AI015", "fs.readFileSync(\nbase + '/' + req.query.path\n);"),
            ("AI015", "fs.promises.readFile(req['body'].path);"),
        ]
        for rule, source in cases:
            with self.subTest(source=source): self.assertIn(rule, rules(source))
        self.assertNotIn("AI014", rules("fetch('https://example.com/userInput');"))
        self.assertNotIn("AI015", rules("fs.readFileSync('toolOutput.txt');"))

    def test_local_external_assignment_and_kill(self):
        self.assertIn("AI014", rules("const target = req.body.url; fetch(target);"))
        self.assertIn("AI015", rules("let target = req.body.path; const next = target; fs.readFile(next);"))
        self.assertNotIn("AI014", rules("let target = req.body.url; target = 'https://example.com'; fetch(target);"))
        self.assertNotIn("AI014", rules("function one() { const target = req.body.url; } function two() { fetch(target); }"))

    def test_logging_labels_do_not_equal_secret_references(self):
        for source in ["console.log('password');", "console.log(`apiKey`);", "logger.info('accessToken label', publicValue);"]:
            with self.subTest(source=source): self.assertNotIn("AI033", rules(source))
        for source in ["console.log('password', password);", "logger.info(`credential ${apiKey}`);", "console.log(config['apiKey']);"]:
            with self.subTest(source=source): self.assertIn("AI033", rules(source))

    def test_privileged_message_field_order_and_template_sources(self):
        for source in [
            "const m = {content: toolOutput, role: 'system'};",
            "const m = {role: 'developer', name: 'policy', content: `prefix ${req.body.prompt}`};",
            "const m = {'content': '\\n' + toolResult, 'role': 'system'};",
        ]:
            with self.subTest(source=source): self.assertIn("AI032", rules(source))
        for source in [
            "const m = {role: 'user', content: toolOutput};",
            "const m = {role: 'system', content: 'toolOutput'};",
            "const a = {role: 'system'}; const b = {content: toolOutput};",
            "const m = {role: 'system', nested: {content: toolOutput}};",
        ]:
            with self.subTest(source=source): self.assertNotIn("AI032", rules(source))

    def test_sql_and_html_dynamic_and_fixed_pairs(self):
        pairs = [
            ("AI036", "db.query('SELECT ' + userInput);", "db.query('SELECT ' + '1');"),
            ("AI036", "db.query(`SELECT ${userInput}`);", r"db.query(`SELECT \${literal}`);"),
            ("AI040", "element.innerHTML = '<p>' + toolOutput;", "element.innerHTML = '<p>' + 'fixed';"),
            ("AI040", "element.insertAdjacentHTML('beforeend', toolOutput);", "element.insertAdjacentHTML('beforeend', '<p>fixed</p>');"),
            ("AI040", "const x = <div dangerouslySetInnerHTML={{__html: toolOutput}}/>;", "const x = <div dangerouslySetInnerHTML={{__html: '<p>fixed</p>'}}/>;"),
        ]
        for rule, unsafe, safe in pairs:
            with self.subTest(rule=rule, source=unsafe): self.assertIn(rule, rules(unsafe))
            with self.subTest(rule=rule, source=safe): self.assertNotIn(rule, rules(safe))

    def test_automatic_semicolon_insertion_preserves_boundaries(self):
        self.assertIn("AI012", rules("const cp = require('child_process')\ncp.exec(userInput)"))
        self.assertIn("AI012", rules("import {exec} from 'child_process'\nconst run = exec\nrun(userInput)"))
        self.assertNotIn("AI040", rules('element.innerHTML = "fixed"\nelement.textContent = toolOutput;'))
        self.assertIn("AI040", rules('element.innerHTML = "prefix"\n + toolOutput;'))

    def test_whitespace_and_comment_metamorphisms(self):
        patterns = [
            ("AI012", ["import", "{", "exec", "as", "run", "}", "from", "'child_process'", ";", "run", "(", "userInput", ")", ";"]),
            ("AI013", ["new", "Function", "(", "'x'", ",", "userInput", ")", ";"]),
            ("AI006", ["const", "cfg", "=", "{", "rejectUnauthorized", ":", "false", "}", ";"]),
            ("AI014", ["fetch", "(", "req", ".", "body", ".", "url", ")", ";"]),
            ("AI032", ["const", "msg", "=", "{", "content", ":", "toolOutput", ",", "role", ":", "'system'", "}", ";"]),
        ]
        for rule, pieces in patterns:
            for separator in (" ", "\n", " /* an inert comment */ ", " // inert comment\n", "\r\n"):
                with self.subTest(rule=rule, separator=separator):
                    self.assertIn(rule, rules(separator.join(pieces)))

    def test_inert_prefix_preserves_rule_and_line_offsets(self):
        source = "import {exec} from 'child_process';\nexec(userInput);"
        prefix = "/* inert eval(userInput) */\nconst text = \"rejectUnauthorized: false\";\n"
        findings = analyze_file("a.js", prefix + source)
        self.assertEqual([("AI012", 4)], [(finding["rule_id"], finding["line"]) for finding in findings])

    def test_js_family_extensions_have_equivalent_results(self):
        source = "import {exec} from 'node:child_process'; exec(userInput);"
        for extension in ("js", "jsx", "ts", "tsx", "mjs", "cjs"):
            with self.subTest(extension=extension): self.assertIn("AI012", rules(source, "agent." + extension))

    def test_long_multiline_arguments_are_not_truncated_by_regex_window(self):
        padding = "\n" + " " * 1500
        self.assertIn("AI013", rules("eval('prefix' +" + padding + "userInput);"))
        self.assertIn("AI012", rules("import {exec} from 'child_process'; exec('echo ' +" + padding + "userInput);"))

    def test_delimiter_and_keyword_literals_remain_data(self):
        for literal in ("{", "}", ",", ";", "(", ")", "import", "function", "const"):
            quoted = json.dumps(literal)
            with self.subTest(literal=literal):
                self.assertNotIn("AI013", rules("eval(" + quoted + ");"))
                self.assertIn("AI013", rules("new Function(" + quoted + ", userInput);"))
                self.assertIn("AI012", rules("import {exec} from 'child_process'; const x = " + quoted + "; exec(userInput);"))

    def test_malformed_and_deep_templates_do_not_crash(self):
        for source in ["const x = `unfinished ${", "eval('unterminated", "const x = `${" * 100 + "userInput" + "}`" * 100, "const x = /[\\/"]:
            with self.subTest(source=source[:80]):
                self.assertIsInstance(analyze_file("a.js", source), list)


if __name__ == "__main__":
    unittest.main()
