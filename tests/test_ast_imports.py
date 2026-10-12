"""AST import policy enforcement and log secret redaction tests."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent.parent / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from surfshark_lite.logs import redact_text


class TestAstImportPolicy(unittest.TestCase):
    """Verify that src/surfshark_lite/ uses only Python stdlib (+ gi in tunnel/{nm,nmloop}.py and optional cryptography in keys.py)."""

    def test_no_forbidden_third_party_imports(self) -> None:
        pkg_root = SRC_ROOT / "surfshark_lite"
        py_files = sorted(pkg_root.rglob("*.py"))
        self.assertGreater(len(py_files), 20)

        stdlib_names = set(sys.stdlib_module_names) | {"surfshark_lite", "__future__"}

        for fpath in py_files:
            rel = fpath.relative_to(pkg_root).as_posix()
            tree = ast.parse(fpath.read_text(encoding="utf-8"), filename=str(fpath))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        self._check_module(rel, top, stdlib_names)
                elif isinstance(node, ast.ImportFrom):
                    if node.level and node.level > 0:
                        continue  # relative import within surfshark_lite
                    if node.module:
                        top = node.module.split(".")[0]
                        self._check_module(rel, top, stdlib_names)

    def _check_module(self, rel_path: str, top_mod: str, stdlib_names: set[str]) -> None:
        if top_mod in stdlib_names:
            return
        if top_mod == "gi" and rel_path in ("tunnel/nm.py", "tunnel/nmloop.py"):
            return
        if top_mod == "cryptography" and rel_path == "keys.py":
            return
        self.fail(f"Forbidden non-stdlib import {top_mod!r} in {rel_path}")


class TestSecretRedaction(unittest.TestCase):
    def test_redacts_jwt_wg_keys_passwords_and_emails(self) -> None:
        sample = (
            'User alice.smith@example.com logged in with password="mySecretPassword123" '
            'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c '
            'and wg key o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo='
        )
        redacted = redact_text(sample)
        self.assertNotIn("mySecretPassword123", redacted)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted)
        self.assertNotIn("o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=", redacted)
        self.assertNotIn("alice.smith@example.com", redacted)
        self.assertIn("a***@example.com", redacted)


if __name__ == "__main__":
    unittest.main()
