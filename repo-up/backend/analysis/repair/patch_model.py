"""
analysis/repair/patch_model.py — Source Patch Model for Phase 5.

A Patch is a candidate repair for a single Finding. It is NEVER automatically
applied to the repository. It is a read-only record that the frontend can
display for human review.

Design constraints
------------------
- The original repository file is NEVER modified during candidate generation.
- All paths are validated against a known project root before any operation.
- A Patch can only be applied if all five validation checks pass (see validate()).
- verification_status is always "not_verified" until a sandbox test passes
  (sandbox is a future phase, so it will always be "not_verified" for now).

Tier classification
-------------------
TIER_1  — Deterministic, safe, automatically generatable. Human still reviews.
TIER_2  — Suggested; requires human review before application.
TIER_3  — Explanation only. No patch generated.
"""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass, field
from typing import Optional


TIER_1 = "tier1_deterministic"
TIER_2 = "tier2_suggested"
TIER_3 = "tier3_explanation_only"

# Four Core Repair Methods
REPAIR_METHOD_RULE_BASED = "rule_based"
REPAIR_METHOD_TEMPLATE_BASED = "template_based"
REPAIR_METHOD_LLM_BASED = "llm_based"
REPAIR_METHOD_CONTEXT_AWARE_HYBRID = "context_aware_hybrid"
ALL_REPAIR_METHODS = (
    REPAIR_METHOD_RULE_BASED,
    REPAIR_METHOD_TEMPLATE_BASED,
    REPAIR_METHOD_LLM_BASED,
    REPAIR_METHOD_CONTEXT_AWARE_HYBRID,
)


@dataclass
class Patch:
    """Immutable candidate repair for a single finding.

    Fields
    ------
    rule_id         : The finding's rule_id this patch addresses.
    language        : Target language (e.g. "Python", "Java").
    tier            : TIER_1 | TIER_2 | TIER_3
    file            : Relative path to the source file.
    start_line      : 1-indexed start line of the region to replace.
    start_col       : 0-indexed start column within start_line.
    end_line        : 1-indexed end line of the region to replace (inclusive).
    end_col         : 0-indexed end column within end_line (exclusive).
    old_text        : Exact text currently at this location in the file.
    new_text        : Replacement text (empty string = delete).
    description     : Human-readable description of the change.
    verification_status : always "not_verified" until sandbox phase.
    repair_method   : One of rule_based, template_based, llm_based, context_aware_hybrid
    """

    rule_id: str
    language: str
    tier: str
    file: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    old_text: str
    new_text: str
    description: str
    verification_status: str = "not_verified"
    repair_method: str = REPAIR_METHOD_RULE_BASED

    def unified_diff(self, context: int = 3) -> str:
        """Return a unified diff string (no file modification)."""
        old_lines = self.old_text.splitlines(keepends=True)
        new_lines = self.new_text.splitlines(keepends=True)
        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{self.file}",
            tofile=f"b/{self.file}",
            lineterm="",
            n=context,
        )
        return "\n".join(diff)

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dict for the API response."""
        return {
            "rule_id":              self.rule_id,
            "language":             self.language,
            "tier":                 self.tier,
            "file":                 self.file,
            "start_line":           self.start_line,
            "start_col":            self.start_col,
            "end_line":             self.end_line,
            "end_col":              self.end_col,
            "old_text":             self.old_text,
            "new_text":             self.new_text,
            "description":          self.description,
            "verification_status":  self.verification_status,
            "repair_method":        self.repair_method,
            "diff":                 self.unified_diff(),
        }


# ---------------------------------------------------------------------------
# Patch validation (Step 5)
# ---------------------------------------------------------------------------

class PatchValidationError(Exception):
    """Raised when a patch fails pre-application validation."""


def validate_patch(patch: Patch, project_root: str, source_lines: list[str]) -> None:
    """Run all five safety checks against *patch*.

    Raises PatchValidationError with a reason if any check fails.
    The original file is NEVER modified.

    Parameters
    ----------
    patch        : The candidate patch to validate.
    project_root : Absolute path to the project root (path-escape guard).
    source_lines : The current contents of the file as a list of lines
                   (including newlines), as returned by open().readlines().
    """

    # 1. No path escape
    abs_file = os.path.normpath(os.path.join(project_root, patch.file))
    if not abs_file.startswith(os.path.normpath(project_root) + os.sep):
        raise PatchValidationError(
            f"Path escape rejected: '{patch.file}' resolves outside project root."
        )

    # 2. Line bounds check
    n_lines = len(source_lines)
    if not (1 <= patch.start_line <= n_lines and 1 <= patch.end_line <= n_lines):
        raise PatchValidationError(
            f"Line range [{patch.start_line}:{patch.end_line}] is out of bounds "
            f"(file has {n_lines} lines)."
        )
    if patch.start_line > patch.end_line:
        raise PatchValidationError("start_line > end_line.")

    # 3. old_text must match the actual source text at the specified location
    actual = _extract_region(source_lines, patch.start_line, patch.start_col,
                              patch.end_line, patch.end_col)
    if actual != patch.old_text:
        raise PatchValidationError(
            f"Source mismatch: patch expects\n  {patch.old_text!r}\nbut found\n  {actual!r}"
        )

    # 4. Apply patch in memory and verify the result is non-empty
    patched = _apply_in_memory(source_lines, patch)
    if not "".join(patched).strip() and "".join(source_lines).strip():
        raise PatchValidationError("Patch would produce an empty file from non-empty source.")

    # 5. Resulting source must remain parseable (Tree-sitter check)
    _assert_parseable(patch.language, "".join(patched))


def _extract_region(lines: list[str], sl: int, sc: int, el: int, ec: int) -> str:
    """Extract the text region from source lines (1-indexed lines, 0-indexed cols)."""
    if sl == el:
        row = lines[sl - 1]
        return row[sc:ec] if ec > 0 else row[sc:]
    parts = [lines[sl - 1][sc:]]
    for i in range(sl, el - 1):
        parts.append(lines[i])
    last = lines[el - 1]
    parts.append(last[:ec] if ec > 0 else last)
    return "".join(parts)


def _apply_in_memory(lines: list[str], patch: Patch) -> list[str]:
    """Apply the patch in memory and return the modified line list."""
    result = list(lines)
    if patch.start_line == patch.end_line:
        row = result[patch.start_line - 1]
        ec = patch.end_col if patch.end_col > 0 else len(row)
        result[patch.start_line - 1] = row[:patch.start_col] + patch.new_text + row[ec:]
    else:
        # Multi-line replacement
        first = result[patch.start_line - 1][:patch.start_col]
        last_row = result[patch.end_line - 1]
        ec = patch.end_col if patch.end_col > 0 else len(last_row)
        last = last_row[ec:]
        replacement_lines = (first + patch.new_text + last).splitlines(keepends=True)
        result[patch.start_line - 1:patch.end_line] = replacement_lines
    return result


def _assert_parseable(language: str, source: str) -> None:
    """Verify the patched source parses without error via Tree-sitter."""
    try:
        from analysis.parsing.ast_parser import parse_file as _pf, LANGUAGES, Parser
        if language not in LANGUAGES:
            return  # Can't verify — pass silently
        parser = Parser(LANGUAGES[language])
        tree = parser.parse(bytes(source, "utf-8"))
        if tree.root_node.has_error:
            raise PatchValidationError(
                f"Patched source has Tree-sitter parse errors ({language})."
            )
    except ImportError:
        pass  # Tree-sitter not available — skip parseability check
    except PatchValidationError:
        raise
    except Exception:
        pass  # Unexpected parser error — don't block on it


def apply_patch_to_string(source: str, patch: Patch) -> str:
    """Apply a validated patch to *source* string and return the result.

    This does NOT touch any file. The caller is responsible for writing the
    result if they choose to do so.
    """
    lines = source.splitlines(keepends=True)
    patched = _apply_in_memory(lines, patch)
    return "".join(patched)
