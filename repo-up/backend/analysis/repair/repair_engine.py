"""
analysis/repair/repair_engine.py — Four-Mode Repair Engine.

Orchestrates candidate patch generation for findings across the four repair modes:
- Method 1: Rule-Based Repair (predefined deterministic rules and patterns)
- Method 2: Template-Based Repair (predefined secure code templates)
- Method 3: LLM-Based Repair (AI language model with minimal localized context)
- Method 4: Context-Aware Hybrid Repair (combines code context, dependency information,
  and cascade repair techniques)

Usage
-----
    from analysis.repair.repair_engine import get_candidate_patch
    response = get_candidate_patch(finding, project_root, mode="context_aware_hybrid")

The engine NEVER modifies files. It only produces candidate Patch objects.
"""

from __future__ import annotations

import importlib
import logging
import os
from typing import Optional

from analysis.repair.patch_model import (
    Patch,
    PatchValidationError,
    validate_patch,
    TIER_1,
    TIER_2,
    TIER_3,
    REPAIR_METHOD_RULE_BASED,
    REPAIR_METHOD_TEMPLATE_BASED,
    REPAIR_METHOD_LLM_BASED,
    REPAIR_METHOD_CONTEXT_AWARE_HYBRID,
)
from analysis.repair.repair_registry import get_repair, RepairSpec
from analysis.repair.template_engine import apply_template, has_template

log = logging.getLogger(__name__)


class RepairResponse:
    """The result of a repair request for a single finding."""

    def __init__(
        self,
        finding: dict,
        repair_available: bool,
        tier: Optional[str],
        patch: Optional[Patch],
        validation_error: Optional[str],
        explanation: Optional[str],
        repair_method: Optional[str] = None,
    ):
        self.finding = finding
        self.repair_available = repair_available
        self.tier = tier
        self.patch = patch
        self.validation_error = validation_error
        self.explanation = explanation
        self.repair_method = repair_method
        self.verification_status = "not_verified"

    def to_dict(self) -> dict:
        d: dict = {
            "finding": self.finding,
            "repair_available": self.repair_available,
            "tier": self.tier,
            "verification_status": self.verification_status,
            "repair_method": self.repair_method or (self.patch.repair_method if self.patch else None),
        }
        if self.patch:
            d["patch"] = self.patch.to_dict()
        if self.validation_error:
            d["validation_error"] = self.validation_error
        if self.explanation:
            d["explanation"] = self.explanation
        return d


# ---------------------------------------------------------------------------
# Individual Repair Mode Generators
# ---------------------------------------------------------------------------

def get_rule_based_patch(finding: dict, project_root: str) -> RepairResponse:
    """Method 1: Rule-Based Repair using predefined syntactic substitution rules."""
    rule_id = finding.get("rule_id", "")
    language = finding.get("language") or _infer_language(finding.get("file", ""))

    spec = get_repair(rule_id, language)
    if spec is None:
        return RepairResponse(
            finding=finding,
            repair_available=False,
            tier=None,
            patch=None,
            validation_error=None,
            explanation=None,
            repair_method=REPAIR_METHOD_RULE_BASED,
        )

    if spec.tier == TIER_3:
        return RepairResponse(
            finding=finding,
            repair_available=False,
            tier=TIER_3,
            patch=None,
            validation_error=None,
            explanation=spec.description,
            repair_method=REPAIR_METHOD_RULE_BASED,
        )

    if spec.tier == TIER_2 or not spec.autofix_available:
        return RepairResponse(
            finding=finding,
            repair_available=True,
            tier=TIER_2,
            patch=None,
            validation_error=None,
            explanation=spec.description,
            repair_method=REPAIR_METHOD_RULE_BASED,
        )

    source_lines = _load_source_lines(finding.get("file", ""), project_root)
    if source_lines is None:
        return RepairResponse(
            finding=finding,
            repair_available=True,
            tier=TIER_1,
            patch=None,
            validation_error="Source file could not be read.",
            explanation=spec.description,
            repair_method=REPAIR_METHOD_RULE_BASED,
        )

    patch = _call_handler(spec, source_lines, finding)
    if patch is None:
        return RepairResponse(
            finding=finding,
            repair_available=True,
            tier=TIER_1,
            patch=None,
            validation_error="Repair handler could not generate a patch (pattern not found on the specified line).",
            explanation=spec.description,
            repair_method=REPAIR_METHOD_RULE_BASED,
        )

    patch.repair_method = REPAIR_METHOD_RULE_BASED

    try:
        validate_patch(patch, project_root, source_lines)
    except PatchValidationError as exc:
        log.warning("Patch validation failed for %s: %s", rule_id, exc)
        return RepairResponse(
            finding=finding,
            repair_available=True,
            tier=TIER_1,
            patch=None,
            validation_error=str(exc),
            explanation=spec.description,
            repair_method=REPAIR_METHOD_RULE_BASED,
        )

    return RepairResponse(
        finding=finding,
        repair_available=True,
        tier=TIER_1,
        patch=patch,
        validation_error=None,
        explanation=spec.description,
        repair_method=REPAIR_METHOD_RULE_BASED,
    )


def get_template_based_patch(finding: dict, project_root: str) -> RepairResponse:
    """Method 2: Template-Based Repair applying predefined secure code templates."""
    source_lines = _load_source_lines(finding.get("file", ""), project_root)
    if source_lines is None:
        return RepairResponse(
            finding=finding,
            repair_available=False,
            tier=None,
            patch=None,
            validation_error="Source file could not be read.",
            explanation=None,
            repair_method=REPAIR_METHOD_TEMPLATE_BASED,
        )

    patch = apply_template(finding, source_lines)
    if patch is None:
        return RepairResponse(
            finding=finding,
            repair_available=False,
            tier=None,
            patch=None,
            validation_error=None,
            explanation="No applicable secure code template found for this finding.",
            repair_method=REPAIR_METHOD_TEMPLATE_BASED,
        )

    patch.repair_method = REPAIR_METHOD_TEMPLATE_BASED

    try:
        validate_patch(patch, project_root, source_lines)
    except PatchValidationError as exc:
        return RepairResponse(
            finding=finding,
            repair_available=True,
            tier=patch.tier,
            patch=None,
            validation_error=f"Template patch validation failed: {exc}",
            explanation=patch.description,
            repair_method=REPAIR_METHOD_TEMPLATE_BASED,
        )

    return RepairResponse(
        finding=finding,
        repair_available=True,
        tier=patch.tier,
        patch=patch,
        validation_error=None,
        explanation=patch.description,
        repair_method=REPAIR_METHOD_TEMPLATE_BASED,
    )


def get_llm_based_patch(finding: dict, project_root: str) -> RepairResponse:
    """Method 3: LLM-Based Repair using minimal localized context."""
    from llm.llm_engine import explain_and_suggest_patch

    explanation, patch = explain_and_suggest_patch(
        finding, project_root, mode="llm_based"
    )

    if patch:
        patch.repair_method = REPAIR_METHOD_LLM_BASED
        return RepairResponse(
            finding=finding,
            repair_available=True,
            tier=TIER_2,
            patch=patch,
            validation_error=None,
            explanation=explanation,
            repair_method=REPAIR_METHOD_LLM_BASED,
        )

    return RepairResponse(
        finding=finding,
        repair_available=bool(explanation and "unavailable" not in explanation),
        tier=TIER_3 if explanation else None,
        patch=None,
        validation_error=None,
        explanation=explanation,
        repair_method=REPAIR_METHOD_LLM_BASED,
    )


def get_hybrid_patch(finding: dict, project_root: str) -> RepairResponse:
    """
    Method 4: Context-Aware Hybrid Repair.
    Combines rule-based checks, secure code templates, and context-enriched LLM prompting
    (with AST enclosing definitions, imports, and file-level dependency graphs).
    """
    # 1. First priority: Deterministic Rule-Based Fix
    resp = get_rule_based_patch(finding, project_root)
    if resp.patch is not None:
        resp.repair_method = REPAIR_METHOD_RULE_BASED
        return resp

    # 2. Second priority: Parameterized Secure Code Template
    resp_tpl = get_template_based_patch(finding, project_root)
    if resp_tpl.patch is not None:
        resp_tpl.repair_method = REPAIR_METHOD_TEMPLATE_BASED
        return resp_tpl

    # 3. Third priority: Context-Aware LLM-Assisted Generation
    from llm.llm_engine import explain_and_suggest_patch

    explanation, patch = explain_and_suggest_patch(
        finding, project_root, mode="context_aware_hybrid"
    )

    if patch:
        patch.repair_method = REPAIR_METHOD_CONTEXT_AWARE_HYBRID
        return RepairResponse(
            finding=finding,
            repair_available=True,
            tier=TIER_2,
            patch=patch,
            validation_error=None,
            explanation=explanation,
            repair_method=REPAIR_METHOD_CONTEXT_AWARE_HYBRID,
        )

    # If it's a known rule with Tier 2 / Tier 3 specification from registry
    if resp.tier in (TIER_2, TIER_3):
        return RepairResponse(
            finding=finding,
            repair_available=resp.repair_available,
            tier=resp.tier,
            patch=None,
            validation_error=resp.validation_error or resp_tpl.validation_error,
            explanation=resp.explanation,
            repair_method=REPAIR_METHOD_CONTEXT_AWARE_HYBRID,
        )

    has_repair = bool(resp.repair_available or resp_tpl.repair_available or (patch is not None))
    return RepairResponse(
        finding=finding,
        repair_available=has_repair,
        tier=resp.tier or (resp_tpl.tier if resp_tpl.repair_available else None),
        patch=None,
        validation_error=resp.validation_error or resp_tpl.validation_error,
        explanation=resp.explanation or resp_tpl.explanation or (explanation if has_repair else None),
        repair_method=REPAIR_METHOD_CONTEXT_AWARE_HYBRID,
    )


# ---------------------------------------------------------------------------
# Master Dispatcher
# ---------------------------------------------------------------------------

def get_candidate_patch(
    finding: dict,
    project_root: str,
    mode: Optional[str] = None,
) -> RepairResponse:
    """
    Generate a candidate patch for a finding according to the requested repair mode.

    Parameters
    ----------
    finding      : Finding dictionary.
    project_root : Absolute path to project root.
    mode         : Repair mode:
                   - 'rule_based' (Method 1)
                   - 'template_based' (Method 2)
                   - 'llm_based' (Method 3)
                   - 'context_aware_hybrid' (Method 4, default)
    """
    clean_mode = (mode or "context_aware_hybrid").lower().strip()

    if clean_mode in ("rule_based", "rule", "method1", "1"):
        return get_rule_based_patch(finding, project_root)
    elif clean_mode in ("template_based", "template", "method2", "2"):
        return get_template_based_patch(finding, project_root)
    elif clean_mode in ("llm_based", "llm", "method3", "3"):
        return get_llm_based_patch(finding, project_root)
    else:
        # Default: Method 4 Context-Aware Hybrid
        return get_hybrid_patch(finding, project_root)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_source_lines(rel_file: str, project_root: str) -> Optional[list[str]]:
    """Safely read the source file. Returns None on any error."""
    if not rel_file:
        return None
    abs_path = os.path.normpath(os.path.join(project_root, rel_file))
    safe_root = os.path.normpath(project_root) + os.sep
    if not abs_path.startswith(safe_root):
        log.warning("Path escape attempt: %s", rel_file)
        return None
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except Exception as exc:
        log.debug("Could not read %s: %s", abs_path, exc)
        return None


def _call_handler(spec: RepairSpec, source_lines: list[str], finding: dict) -> Optional[Patch]:
    """Dynamically load and call the repair handler."""
    if not spec.handler_module or not spec.handler_fn:
        return None
    try:
        mod = importlib.import_module(spec.handler_module)
        fn = getattr(mod, spec.handler_fn)
        return fn(source_lines, finding)
    except Exception as exc:
        log.exception("Repair handler %s.%s failed: %s", spec.handler_module, spec.handler_fn, exc)
        return None


def _infer_language(filepath: str) -> str:
    """Infer language from file extension when not set in finding."""
    ext_map = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".java": "Java",
        ".cpp": "C++",
        ".cc": "C++",
        ".cxx": "C++",
        ".hpp": "C++",
        ".h": "C++",
    }
    ext = os.path.splitext(filepath)[-1].lower()
    return ext_map.get(ext, "")
