"""
test_four_repair_modes.py — Comprehensive tests for all 4 repair modes:
1. Method 1 – Rule-Based Repair
2. Method 2 – Template-Based Repair
3. Method 3 – LLM-Based Repair
4. Method 4 – Context-Aware Hybrid Repair
"""

import os
import sys
import tempfile
import unittest

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(__file__))

from analysis.repair import (
    REPAIR_METHOD_RULE_BASED,
    REPAIR_METHOD_TEMPLATE_BASED,
    REPAIR_METHOD_LLM_BASED,
    REPAIR_METHOD_CONTEXT_AWARE_HYBRID,
    get_candidate_patch,
    get_rule_based_patch,
    get_template_based_patch,
    get_llm_based_patch,
    get_hybrid_patch,
    list_templates,
)
from llm.context_builder import (
    build_minimal_context,
    build_hybrid_context,
    extract_ast_context,
    extract_graph_context,
    redact_secrets,
)


class TestFourRepairModes(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    # -----------------------------------------------------------------------
    # Method 1: Rule-Based Repair
    # -----------------------------------------------------------------------
    def test_method_1_rule_based_repair(self):
        test_file = os.path.join(self.root, "crypto_check.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("import hashlib\n\ndef hash_data(val):\n    return hashlib.md5(val.encode())\n")

        finding = {
            "rule_id": "SEC-WEAK-CRYPTO",
            "file": "crypto_check.py",
            "line": 4,
            "language": "Python",
            "description": "Weak MD5 hash algorithm detected.",
        }

        # Request Method 1 specifically
        resp = get_candidate_patch(finding, self.root, mode="rule_based")
        self.assertTrue(resp.repair_available)
        self.assertIsNotNone(resp.patch)
        self.assertEqual(resp.repair_method, REPAIR_METHOD_RULE_BASED)
        self.assertEqual(resp.patch.repair_method, REPAIR_METHOD_RULE_BASED)
        self.assertIn("hashlib.sha256", resp.patch.new_text)

    # -----------------------------------------------------------------------
    # Method 2: Template-Based Repair
    # -----------------------------------------------------------------------
    def test_method_2_template_catalog(self):
        templates = list_templates()
        self.assertGreaterEqual(len(templates), 4)
        template_ids = [t["template_id"] for t in templates]
        self.assertIn("TPL-PY-SAFE-ASSERT", template_ids)
        self.assertIn("TPL-PY-TRY-EXCEPT", template_ids)
        self.assertIn("TPL-JS-TRY-CATCH", template_ids)
        self.assertIn("TPL-PY-SAFE-SUBPROCESS", template_ids)

    def test_method_2_safe_assert_template(self):
        test_file = os.path.join(self.root, "auth_check.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("def verify_user(user):\n    assert user.is_authenticated, \"Access denied\"\n")

        finding = {
            "rule_id": "SEC-UNSAFE-ASSERT",
            "file": "auth_check.py",
            "line": 2,
            "language": "Python",
            "description": "Unsafe assert statement used in security guard.",
        }

        resp = get_candidate_patch(finding, self.root, mode="template_based")
        self.assertTrue(resp.repair_available)
        self.assertIsNotNone(resp.patch)
        self.assertEqual(resp.repair_method, REPAIR_METHOD_TEMPLATE_BASED)
        self.assertEqual(resp.patch.repair_method, REPAIR_METHOD_TEMPLATE_BASED)
        self.assertIn("if not (user.is_authenticated):", resp.patch.new_text)
        self.assertIn("raise AssertionError(\"Access denied\")", resp.patch.new_text)

    def test_method_2_exception_wrap_template(self):
        test_file = os.path.join(self.root, "fetcher.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("def do_fetch(url):\n    res = requests.get(url)\n    return res.text\n")

        finding = {
            "rule_id": "SEC-CWE-703",
            "file": "fetcher.py",
            "line": 2,
            "language": "Python",
            "description": "Missing exception handling around network call.",
        }

        resp = get_candidate_patch(finding, self.root, mode="template_based")
        self.assertTrue(resp.repair_available)
        self.assertIsNotNone(resp.patch)
        self.assertEqual(resp.repair_method, REPAIR_METHOD_TEMPLATE_BASED)
        self.assertIn("try:", resp.patch.new_text)
        self.assertIn("except Exception as exc:", resp.patch.new_text)

    # -----------------------------------------------------------------------
    # Method 3: LLM-Based Repair (Minimal Context Baseline)
    # -----------------------------------------------------------------------
    def test_method_3_llm_based_repair(self):
        test_file = os.path.join(self.root, "service.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("def parse(data):\n    return data\n")

        finding = {
            "rule_id": "SEC-UNKNOWN-LOGIC",
            "file": "service.py",
            "line": 2,
            "language": "Python",
            "description": "Potential logic issue.",
        }

        os.environ["LLM_TEST_MOCK_PATCH"] = "1"
        try:
            resp = get_candidate_patch(finding, self.root, mode="llm_based")
            self.assertTrue(resp.repair_available)
            self.assertEqual(resp.repair_method, REPAIR_METHOD_LLM_BASED)
            self.assertIsNotNone(resp.patch)
            self.assertEqual(resp.patch.repair_method, REPAIR_METHOD_LLM_BASED)
            self.assertIn("[AI Fix Applied]", resp.patch.new_text)
        finally:
            os.environ.pop("LLM_TEST_MOCK_PATCH", None)

    # -----------------------------------------------------------------------
    # Method 4: Context-Aware Hybrid Repair
    # -----------------------------------------------------------------------
    def test_method_4_context_extraction(self):
        test_file = os.path.join(self.root, "complex_calc.py")
        code = (
            "import os\n"
            "from math import sqrt\n\n"
            "class MathEngine:\n"
            "    def calculate(self, x):\n"
            "        return sqrt(x)\n"
        )
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(code)

        finding = {
            "rule_id": "SEC-CUSTOM",
            "file": "complex_calc.py",
            "line": 6,
            "language": "Python",
            "description": "Calculation check.",
        }

        # Check AST context extraction
        ast_ctx = extract_ast_context("complex_calc.py", code, 6, "Python")
        self.assertTrue(any("sqrt" in imp for imp in ast_ctx["imports"]))
        self.assertIsNotNone(ast_ctx["enclosing_definition"])
        self.assertIn("Function calculate", ast_ctx["enclosing_definition"])

        # Check Hybrid context packaging
        ctx = build_hybrid_context(finding, self.root, runtime_output="Error in execution")
        self.assertEqual(ctx["mode"], "context_aware_hybrid")
        self.assertIn("ast_context", ctx)
        self.assertIn("graph_context", ctx)
        self.assertIn("runtime_evidence", ctx)

    def test_method_4_hybrid_cascade(self):
        # 1. When rule-based is available, hybrid chooses rule-based
        test_file = os.path.join(self.root, "app.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("import yaml\n\ndef load_cfg(s):\n    return yaml.load(s)\n")

        finding_rule = {
            "rule_id": "SEC-CWE-502",
            "file": "app.py",
            "line": 4,
            "language": "Python",
            "description": "Unsafe yaml.load",
        }
        resp = get_candidate_patch(finding_rule, self.root, mode="context_aware_hybrid")
        self.assertTrue(resp.repair_available)
        self.assertEqual(resp.repair_method, REPAIR_METHOD_RULE_BASED)

        # 2. When rule-based is NOT available but template is, hybrid cascades to template-based
        test_file2 = os.path.join(self.root, "guard.py")
        with open(test_file2, "w", encoding="utf-8") as f:
            f.write("def check_admin(user):\n    assert user.is_super, \"Denied\"\n")

        finding_tpl = {
            "rule_id": "SEC-UNSAFE-ASSERT",
            "file": "guard.py",
            "line": 2,
            "language": "Python",
            "description": "Unsafe assert",
        }
        resp2 = get_candidate_patch(finding_tpl, self.root, mode="context_aware_hybrid")
        self.assertTrue(resp2.repair_available)
        self.assertEqual(resp2.repair_method, REPAIR_METHOD_TEMPLATE_BASED)


if __name__ == "__main__":
    unittest.main()
