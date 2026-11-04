"""
analysis/repair/__init__.py — Four-Mode Repair Subsystem.
"""

from .patch_model import (
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
    ALL_REPAIR_METHODS,
)
from .repair_engine import (
    RepairResponse,
    get_candidate_patch,
    get_rule_based_patch,
    get_template_based_patch,
    get_llm_based_patch,
    get_hybrid_patch,
)
from .template_engine import (
    apply_template,
    list_templates,
    has_template,
)
from .repair_registry import (
    get_repair,
    list_repairs,
    has_autofix,
)

__all__ = [
    "Patch",
    "PatchValidationError",
    "validate_patch",
    "TIER_1",
    "TIER_2",
    "TIER_3",
    "REPAIR_METHOD_RULE_BASED",
    "REPAIR_METHOD_TEMPLATE_BASED",
    "REPAIR_METHOD_LLM_BASED",
    "REPAIR_METHOD_CONTEXT_AWARE_HYBRID",
    "ALL_REPAIR_METHODS",
    "RepairResponse",
    "get_candidate_patch",
    "get_rule_based_patch",
    "get_template_based_patch",
    "get_llm_based_patch",
    "get_hybrid_patch",
    "apply_template",
    "list_templates",
    "has_template",
    "get_repair",
    "list_repairs",
    "has_autofix",
]
