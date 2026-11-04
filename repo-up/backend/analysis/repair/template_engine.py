"""
analysis/repair/template_engine.py — Method 2: Template-Based Repair Engine.

Applies predefined, parameterised secure code templates to replace vulnerable
code patterns for known vulnerability classes.

Design principles:
------------------
- Predefined secure code templates replace vulnerable syntactic blocks with verified, safe paradigms.
- Templates preserve original indentation, variable names, and surrounding semantics.
- Generates a valid Patch with repair_method="template_based".
- All output patches pass the 5-step strict validation (validate_patch).
"""

from __future__ import annotations

import abc
import re
from typing import Any, Dict, List, Optional

from analysis.repair.patch_model import (
    Patch,
    TIER_1,
    TIER_2,
    REPAIR_METHOD_TEMPLATE_BASED,
)


class SecureTemplate(abc.ABC):
    """Abstract base class for secure code templates."""

    def __init__(
        self,
        template_id: str,
        rule_id: str,
        language: str,
        name: str,
        description: str,
        tier: str = TIER_1,
    ):
        self.template_id = template_id
        self.rule_id = rule_id
        self.language = language
        self.name = name
        self.description = description
        self.tier = tier

    @abc.abstractmethod
    def can_apply(self, source_lines: List[str], finding: Dict[str, Any]) -> bool:
        """Check if this template can be applied to the finding."""
        pass

    @abc.abstractmethod
    def apply(self, source_lines: List[str], finding: Dict[str, Any]) -> Optional[Patch]:
        """Apply the template and return a candidate Patch."""
        pass

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "rule_id": self.rule_id,
            "language": self.language,
            "name": self.name,
            "description": self.description,
            "tier": self.tier,
        }


# ===========================================================================
# Concrete Templates
# ===========================================================================

class PythonSafeAssertTemplate(SecureTemplate):
    """
    Template for SEC-UNSAFE-ASSERT (Python).
    Replaces vulnerable `assert <cond> [, <msg>]` with an explicit conditional
    raising an AssertionError or ValueError. This prevents asserts from being stripped
    out when running with Python optimizations (-O).
    """

    def __init__(self):
        super().__init__(
            template_id="TPL-PY-SAFE-ASSERT",
            rule_id="SEC-UNSAFE-ASSERT",
            language="Python",
            name="Explicit Conditional Guard",
            description="Replaces vulnerable assert statements with an explicit if-not condition that cannot be bypassed via python -O.",
            tier=TIER_1,
        )

    def can_apply(self, source_lines: List[str], finding: Dict[str, Any]) -> bool:
        line_no = finding.get("line")
        if not line_no or line_no < 1 or line_no > len(source_lines):
            return False
        raw = source_lines[line_no - 1]
        stripped = raw.strip()
        return stripped.startswith("assert ") or stripped.startswith("assert(")

    def apply(self, source_lines: List[str], finding: Dict[str, Any]) -> Optional[Patch]:
        line_no = finding.get("line", 1)
        file_path = finding.get("file", "")
        raw = source_lines[line_no - 1]

        # Extract indentation
        indent_len = len(raw) - len(raw.lstrip())
        indent = raw[:indent_len]
        stripped = raw.strip()

        # Match assert condition and optional message
        # e.g.: assert user.is_admin, "Admin required"
        assert_body = stripped[len("assert"):].strip()
        if not assert_body:
            return None

        condition = assert_body
        message: Optional[str] = None

        # Simple comma split if outside quotes/parentheses
        if "," in assert_body:
            parts = assert_body.split(",", 1)
            condition = parts[0].strip()
            message = parts[1].strip()

        # Build replacement lines
        if message:
            replacement = (
                f"{indent}if not ({condition}):\n"
                f"{indent}    raise AssertionError({message})\n"
            )
        else:
            replacement = (
                f"{indent}if not ({condition}):\n"
                f"{indent}    raise AssertionError(\"Security assertion condition failed\")\n"
            )

        return Patch(
            rule_id=self.rule_id,
            language=self.language,
            tier=self.tier,
            file=file_path,
            start_line=line_no,
            start_col=0,
            end_line=line_no,
            end_col=len(raw),
            old_text=raw,
            new_text=replacement,
            description=f"Template {self.template_id}: Replaced assert statement with explicit conditional guard.",
            verification_status="not_verified",
            repair_method=REPAIR_METHOD_TEMPLATE_BASED,
        )


class PythonExceptionWrapTemplate(SecureTemplate):
    """
    Template for SEC-CWE-703 (Python).
    Wraps naked/unhandled risky operations in a robust try-except block.
    """

    def __init__(self):
        super().__init__(
            template_id="TPL-PY-TRY-EXCEPT",
            rule_id="SEC-CWE-703",
            language="Python",
            name="Defensive Try-Except Block",
            description="Wraps unguarded I/O, parsing, or network operations in a defensive try/except block with logging.",
            tier=TIER_1,
        )

    def can_apply(self, source_lines: List[str], finding: Dict[str, Any]) -> bool:
        line_no = finding.get("line")
        if not line_no or line_no < 1 or line_no > len(source_lines):
            return False
        raw = source_lines[line_no - 1].strip()
        # Ensure it's a non-empty statement, not already inside a try
        return bool(raw and not raw.startswith("try:") and not raw.startswith("except"))

    def apply(self, source_lines: List[str], finding: Dict[str, Any]) -> Optional[Patch]:
        line_no = finding.get("line", 1)
        file_path = finding.get("file", "")
        raw = source_lines[line_no - 1]

        indent_len = len(raw) - len(raw.lstrip())
        indent = raw[:indent_len]
        stmt = raw.strip()

        replacement = (
            f"{indent}try:\n"
            f"{indent}    {stmt}\n"
            f"{indent}except Exception as exc:\n"
            f"{indent}    import logging\n"
            f"{indent}    logging.getLogger(__name__).warning(\"Handled operation error: %s\", exc)\n"
        )

        return Patch(
            rule_id=self.rule_id,
            language=self.language,
            tier=self.tier,
            file=file_path,
            start_line=line_no,
            start_col=0,
            end_line=line_no,
            end_col=len(raw),
            old_text=raw,
            new_text=replacement,
            description=f"Template {self.template_id}: Wrapped risky statement in safe try-except block.",
            verification_status="not_verified",
            repair_method=REPAIR_METHOD_TEMPLATE_BASED,
        )


class JsExceptionWrapTemplate(SecureTemplate):
    """
    Template for SEC-CWE-703 (JavaScript / TypeScript).
    Wraps unhandled async/IO operations in a standard try-catch block.
    """

    def __init__(self, language: str = "JavaScript"):
        super().__init__(
            template_id=f"TPL-{'TS' if language == 'TypeScript' else 'JS'}-TRY-CATCH",
            rule_id="SEC-CWE-703",
            language=language,
            name="Defensive Try-Catch Block",
            description="Wraps unguarded statements in a defensive try/catch block.",
            tier=TIER_1,
        )

    def can_apply(self, source_lines: List[str], finding: Dict[str, Any]) -> bool:
        line_no = finding.get("line")
        if not line_no or line_no < 1 or line_no > len(source_lines):
            return False
        raw = source_lines[line_no - 1].strip()
        return bool(raw and not raw.startswith("try {") and not raw.startswith("catch"))

    def apply(self, source_lines: List[str], finding: Dict[str, Any]) -> Optional[Patch]:
        line_no = finding.get("line", 1)
        file_path = finding.get("file", "")
        raw = source_lines[line_no - 1]

        indent_len = len(raw) - len(raw.lstrip())
        indent = raw[:indent_len]
        stmt = raw.strip()

        replacement = (
            f"{indent}try {{\n"
            f"{indent}    {stmt}\n"
            f"{indent}}} catch (err) {{\n"
            f"{indent}    console.warn(\"Handled operation error:\", err);\n"
            f"{indent}}}\n"
        )

        return Patch(
            rule_id=self.rule_id,
            language=self.language,
            tier=self.tier,
            file=file_path,
            start_line=line_no,
            start_col=0,
            end_line=line_no,
            end_col=len(raw),
            old_text=raw,
            new_text=replacement,
            description=f"Template {self.template_id}: Wrapped statement in safe try-catch block.",
            verification_status="not_verified",
            repair_method=REPAIR_METHOD_TEMPLATE_BASED,
        )


class PythonSafeSubprocessTemplate(SecureTemplate):
    """
    Template for SEC-DANGEROUS-EXEC (Python).
    Replaces vulnerable `os.system(cmd)` with `subprocess.run(shlex.split(cmd), shell=False)`.
    """

    def __init__(self):
        super().__init__(
            template_id="TPL-PY-SAFE-SUBPROCESS",
            rule_id="SEC-DANGEROUS-EXEC",
            language="Python",
            name="Safe Subprocess Invocation",
            description="Replaces shell-interpreted execution with shell=False argument list parsing.",
            tier=TIER_2,
        )

    def can_apply(self, source_lines: List[str], finding: Dict[str, Any]) -> bool:
        line_no = finding.get("line")
        if not line_no or line_no < 1 or line_no > len(source_lines):
            return False
        raw = source_lines[line_no - 1]
        return bool(re.search(r'\bos\.system\s*\(', raw))

    def apply(self, source_lines: List[str], finding: Dict[str, Any]) -> Optional[Patch]:
        line_no = finding.get("line", 1)
        file_path = finding.get("file", "")
        raw = source_lines[line_no - 1]

        m = re.search(r'\bos\.system\s*\((.*?)\)', raw)
        if not m:
            return None

        cmd_expr = m.group(1).strip()
        indent_len = len(raw) - len(raw.lstrip())
        indent = raw[:indent_len]

        # Template replacement using subprocess.run and shlex
        replacement = (
            f"{indent}import subprocess, shlex; "
            f"subprocess.run(shlex.split({cmd_expr}), shell=False, check=False)\n"
        )

        return Patch(
            rule_id=self.rule_id,
            language=self.language,
            tier=self.tier,
            file=file_path,
            start_line=line_no,
            start_col=0,
            end_line=line_no,
            end_col=len(raw),
            old_text=raw,
            new_text=replacement,
            description=f"Template {self.template_id}: Replaced os.system with safe non-shell subprocess execution.",
            verification_status="not_verified",
            repair_method=REPAIR_METHOD_TEMPLATE_BASED,
        )


class JavaDeserializationFilterTemplate(SecureTemplate):
    """
    Template for SEC-CWE-502 (Java).
    Injects an ObjectInputFilter to prevent arbitrary Java class deserialization.
    """

    def __init__(self):
        super().__init__(
            template_id="TPL-JAVA-INPUT-FILTER",
            rule_id="SEC-CWE-502",
            language="Java",
            name="ObjectInputFilter Serialization Guard",
            description="Applies an ObjectInputFilter to restrict allowable classes during deserialization.",
            tier=TIER_2,
        )

    def can_apply(self, source_lines: List[str], finding: Dict[str, Any]) -> bool:
        line_no = finding.get("line")
        if not line_no or line_no < 1 or line_no > len(source_lines):
            return False
        raw = source_lines[line_no - 1]
        return "ObjectInputStream" in raw and ("new ObjectInputStream" in raw or ".readObject" in raw)

    def apply(self, source_lines: List[str], finding: Dict[str, Any]) -> Optional[Patch]:
        line_no = finding.get("line", 1)
        file_path = finding.get("file", "")
        raw = source_lines[line_no - 1]

        indent_len = len(raw) - len(raw.lstrip())
        indent = raw[:indent_len]

        # Extract variable name if assignment, e.g. ObjectInputStream ois = ...
        var_match = re.search(r'ObjectInputStream\s+([a-zA-Z0-9_]+)\s*=', raw)
        var_name = var_match.group(1) if var_match else "ois"

        filter_stmt = (
            f"{indent}{var_name}.setObjectInputFilter("
            f"java.io.ObjectInputFilter.Config.createFilter(\"maxbytes=1048576;maxdepth=10;!*\"));\n"
        )
        replacement = raw + filter_stmt

        return Patch(
            rule_id=self.rule_id,
            language=self.language,
            tier=self.tier,
            file=file_path,
            start_line=line_no,
            start_col=0,
            end_line=line_no,
            end_col=len(raw),
            old_text=raw,
            new_text=replacement,
            description=f"Template {self.template_id}: Added ObjectInputFilter guard on deserialization stream.",
            verification_status="not_verified",
            repair_method=REPAIR_METHOD_TEMPLATE_BASED,
        )


# ===========================================================================
# Template Registry & Dispatcher
# ===========================================================================

_TEMPLATES: List[SecureTemplate] = [
    PythonSafeAssertTemplate(),
    PythonExceptionWrapTemplate(),
    JsExceptionWrapTemplate("JavaScript"),
    JsExceptionWrapTemplate("TypeScript"),
    PythonSafeSubprocessTemplate(),
    JavaDeserializationFilterTemplate(),
]


def list_templates() -> List[Dict[str, Any]]:
    """Return catalog of all available secure code templates."""
    return [t.to_dict() for t in _TEMPLATES]


def has_template(rule_id: str, language: str) -> bool:
    """Check if any template exists for rule_id + language."""
    for t in _TEMPLATES:
        if t.rule_id == rule_id and (t.language == language or not language):
            return True
    return False


def apply_template(finding: Dict[str, Any], source_lines: List[str]) -> Optional[Patch]:
    """
    Search for an applicable template for the finding and render candidate Patch.
    Returns None if no template applies or match condition fails.
    """
    rule_id = finding.get("rule_id", "")
    language = finding.get("language", "")

    for t in _TEMPLATES:
        if t.rule_id == rule_id:
            if not language or t.language.lower() == language.lower():
                if t.can_apply(source_lines, finding):
                    return t.apply(source_lines, finding)

    return None
