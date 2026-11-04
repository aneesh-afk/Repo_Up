import os
from typing import Optional, Tuple
from .provider import get_provider
from .context_builder import build_context
from analysis.repair.patch_model import (
    Patch,
    validate_patch,
    TIER_2,
    REPAIR_METHOD_LLM_BASED,
    REPAIR_METHOD_CONTEXT_AWARE_HYBRID,
)

def explain_and_suggest_patch(
    finding_dict: dict,
    project_root: str,
    mode: str = "context_aware_hybrid",
    runtime_output: Optional[str] = None,
) -> Tuple[str, Optional[Patch]]:
    """
    Generates an explanation and optional candidate patch using the configured LLM.
    Supports:
      - mode="llm_based": Method 3 (minimal context baseline)
      - mode="context_aware_hybrid": Method 4 (AST + dependency-graph + runtime evidence)
    Strictly validates any returned patch through Phase 5 validation.
    """
    provider = get_provider()
    if not provider:
        return ("AI Explanation unavailable. No provider configured.", None)
        
    context = build_context(
        finding_dict,
        project_root,
        mode=mode,
        runtime_output=runtime_output,
    )
    
    explanation = "AI Explanation unavailable."
    try:
        explanation = provider.generate_explanation(context)
    except Exception:
        explanation = "AI Explanation failed due to an error."
        
    patch_obj = None
    target_repair_method = (
        REPAIR_METHOD_CONTEXT_AWARE_HYBRID
        if mode == "context_aware_hybrid"
        else REPAIR_METHOD_LLM_BASED
    )
    try:
        patch_dict = provider.generate_patch(context)
        if patch_dict:
            file_path = patch_dict.get("file", finding_dict.get("file"))
            old_text = patch_dict.get("old_text", "")
            new_text = patch_dict.get("new_text", "")
            
            # Route through standard Patch
            patch_obj = Patch(
                rule_id=finding_dict.get("rule_id", "UNKNOWN"),
                language=finding_dict.get("language", "UNKNOWN"),
                tier=TIER_2,
                file=file_path,
                start_line=finding_dict.get("line", 1),
                start_col=0,
                end_line=finding_dict.get("line", 1),
                end_col=0,
                old_text=old_text,
                new_text=new_text,
                description=f"AI suggestion ({target_repair_method}) — not yet verified.",
                verification_status="not_verified",
                repair_method=target_repair_method,
            )
            
            # Step 5: Patch Validation
            abs_path = os.path.join(project_root, file_path)
            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_lines = f.readlines()
                
            errors = None
            try:
                validate_patch(patch_obj, project_root, source_lines)
            except Exception as e:
                errors = str(e)
                
            if errors:
                patch_obj = None  # Safely discard unsafe LLM hallucinations
                explanation += f"\n\n*(Note: An AI patch was generated but discarded due to validation errors: {errors})*"
    except Exception:
        pass
        
    return explanation, patch_obj
