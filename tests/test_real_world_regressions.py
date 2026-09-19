"""Focused detector regressions prompted by development-visible public scans.

These are small synthetic cases, not copies of upstream source or real secrets.
"""
import json
import unittest

from ai_security_scan.analyzer import analyze_file


def ids(source, path="agent.py"):
    return {f["rule_id"] for f in analyze_file(path, source)}


class RealWorldDetectorRegressions(unittest.TestCase):
    def test_private_key_header_without_material_is_not_a_leak(self):
        for text in ["-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----...",
                     "-----BEGIN PRIVATE KEY-----\nexample\n", "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"]:
            with self.subTest(text=text):
                self.assertNotIn("AI011", ids(text, "key.pem"))
                self.assertNotIn("AI011", ids('"""Example: ' + text + '"""', "agent.py"))

    def test_plausible_private_material_remains_detected_in_docstrings(self):
        body = "M" * 64
        for kind in ["", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "]:
            text = "-----BEGIN " + kind + "PRIVATE KEY-----\n" + body + "\n-----END " + kind + "PRIVATE KEY-----"
            with self.subTest(kind=kind):
                self.assertIn("AI011", ids(text, "key.pem"))
                self.assertIn("AI011", ids('"""Example: ' + text + '"""', "agent.py"))
                self.assertIn("AI011", ids("material = " + repr(text), "agent.py"))

    def test_truncated_and_legacy_encrypted_private_material_detected(self):
        for body in ["M" * 64, "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0000000000000000\n\n" + "M" * 64]:
            self.assertIn("AI011", ids("-----BEGIN RSA PRIVATE KEY-----\n" + body, "key.pem"))
        self.assertNotIn("AI011", ids("-----BEGIN PUBLIC KEY-----\n" + "M" * 64, "key.pem"))

    def test_exact_sdk_sentinels_are_placeholders_across_source_and_config(self):
        for placeholder in ["api-key-not-set", "codex-subscription-auth"]:
            for path, source in [
                ("agent.py", "api_key = " + repr(placeholder) + "\nclient(api_key=api_key)"),
                ("agent.ts", "const api_key = " + json.dumps(placeholder) + ";"),
                ("config.json", json.dumps({"api_key": placeholder})),
                ("config.yaml", "api_key: " + placeholder),
            ]:
                with self.subTest(placeholder=placeholder, path=path):
                    self.assertNotIn("AI010", ids(source, path))
                    self.assertIn("AI010", ids(source.replace(placeholder, placeholder + "-real-extra-material"), path))

    def test_error_roles_require_both_role_and_narrow_message(self):
        for path, template in [("agent.py", "INVALID_API_KEY_ERROR = {!r}"),
                               ("agent.ts", "const INVALID_API_KEY_ERROR = {!r};")]:
            self.assertNotIn("AI010", ids(template.format("Invalid API key"), path))
            self.assertIn("AI010", ids(template.format("actual-sensitive-credential-4827"), path))
        self.assertIn("AI010", ids("password = 'Invalid API key'"))
        self.assertIn("AI010", ids("api_key_error = 'sk-" + "A" * 40 + "'"))

    def test_docker_default_final_stage_effective_user(self):
        cases = [
            ("FROM base\nUSER root\nRUN install\nUSER app\n", False),
            ("FROM base\nUSER app\nUSER root\n", True),
            ("FROM base AS builder\nUSER root\nFROM scratch\nUSER app\n", False),
            ("FROM base AS builder\nUSER root\nFROM other\n", False),
            ("FROM base AS builder\nUSER root\nFROM builder AS final\n", True),
            ("FROM base AS builder\nUSER root\nUSER app\nFROM builder AS final\n", False),
            ("FROM base AS builder\nUSER root\nFROM builder AS final\nUSER app\n", False),
            ("FROM base\nUSER ${RUNTIME_USER}\n", False),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual("AI021" in ids(source, "Dockerfile"), expected)

    def test_docker_root_spellings_and_continued_user(self):
        for user in ["root", "0", "0000", "0:1000", "root:app"]:
            with self.subTest(user=user):
                self.assertIn("AI021", ids("FROM base\nuSeR " + user, "Dockerfile"))
        self.assertIn("AI021", ids("FROM base\nUSER \\\n root\n", "Dockerfile"))
        self.assertIn("AI021", ids("# escape=`\nFROM base\nUSER `\n root\n", "Dockerfile"))
        self.assertNotIn("AI021", ids("FROM base\nUSER ROOT", "Dockerfile"))

    def test_docker_embedded_instruction_text_is_not_a_user_change(self):
        for source in [
            "FROM base\nUSER app\nRUN echo \\\n USER root\n",
            "FROM base\nUSER app\nRUN <<EOF\nUSER root\nEOF\n",
            "FROM base\nUSER app\nCOPY <<'EOF' /tmp/config\nUSER root\nEOF\n",
            "FROM base\nUSER app\nRUN <<ONE <<TWO\nUSER root\nONE\nUSER root\nTWO\n",
            "FROM base\nUSER app\nRUN <<123\nUSER root\n123\n",
            "FROM base\nUSER app\nCOPY <<'end-marker' /tmp/config\nUSER root\nend-marker\n",
            "FROM base\nUSER app\nRUN echo \\\n# Docker removes comment-only lines\n\n USER root\n",
            "FROM base\nUSER app\nRUN <<EOF\n EOF\nUSER root\nEOF\n",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("AI021", ids(source, "Dockerfile"))
        self.assertIn("AI021", ids("FROM base\nUSER app\nRUN <<-EOF\n\tEOF\nUSER root\n", "Dockerfile"))

    def test_docker_root_evidence_refers_to_effective_instruction(self):
        report = analyze_file("Dockerfile", "FROM base\nUSER root\nUSER app\nUSER 0\n")
        finding = next(f for f in report if f["rule_id"] == "AI021")
        self.assertEqual(finding["line"], 4)
        self.assertIn("USER 0", finding["evidence"])


if __name__ == "__main__":
    unittest.main()
