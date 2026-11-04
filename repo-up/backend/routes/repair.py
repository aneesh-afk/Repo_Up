"""
routes/repair.py — POST /repair

Accepts a finding dict, session_id, and optional repair mode.
Returns a candidate patch produced by one of the four repair modes:
- Method 1: rule_based
- Method 2: template_based
- Method 3: llm_based
- Method 4: context_aware_hybrid (default)

Response shape
--------------
{
    "finding": {...},
    "repair_available": bool,
    "repair_method": "rule_based" | "template_based" | "llm_based" | "context_aware_hybrid" | null,
    "tier": "tier1_deterministic" | "tier2_suggested" | "tier3_explanation_only" | null,
    "verification_status": "not_verified",
    "patch": {
        "rule_id": "...",
        "language": "...",
        "file": "...",
        "start_line": int,
        "old_text": "...",
        "new_text": "...",
        "diff": "...",
        "repair_method": "...",
        "verification_status": "...",
        "verification_details": {...}
    } | null,
    "validation_error": "..." | null,
    "explanation": "..."
}

The endpoint never modifies files on disk.
"""

from typing import Optional
import logging
import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter()
log = logging.getLogger(__name__)

from services.upload_service import SESSION_STORE


class RepairRequest(BaseModel):
    session_id: str
    finding: dict
    mode: Optional[str] = "context_aware_hybrid"


@router.post("/repair")
async def request_repair(body: RepairRequest) -> JSONResponse:
    """Generate a candidate patch for a finding across the four repair modes.

    Does NOT apply the patch to the user's files.
    All candidate patches are verified in a throwaway isolation sandbox.
    """
    session_id = body.session_id
    finding = body.finding
    mode = (body.mode or "context_aware_hybrid").lower().strip()

    # Resolve project_root from session store
    session = SESSION_STORE.get(session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail={
                "error": {
                    "code": "SESSION_NOT_FOUND",
                    "message": "Session not found or expired. Please re-upload the project.",
                }
            },
        )

    project_root = session.get("project_path", "")
    if not project_root or not os.path.isdir(project_root):
        raise HTTPException(
            status_code=404,
            detail={
                "error": {
                    "code": "PROJECT_PATH_MISSING",
                    "message": "Project path for this session is no longer available.",
                }
            },
        )

    try:
        from analysis.repair.repair_engine import get_candidate_patch
        from verification.runner import verify_patch
        from analysis.finding import Finding

        response = get_candidate_patch(finding, project_root, mode=mode)

        # Fallback to LLM if mode permits and no patch was generated
        if not response.patch and mode in ("llm_based", "context_aware_hybrid", "auto"):
            from llm.llm_engine import explain_and_suggest_patch
            llm_explanation, llm_patch = explain_and_suggest_patch(
                finding, project_root, mode=mode
            )

            if llm_explanation and "unavailable" not in llm_explanation:
                response.explanation = llm_explanation

            if llm_patch:
                response.patch = llm_patch
                response.tier = "tier2_suggested"
                response.repair_method = llm_patch.repair_method
                response.repair_available = True

        # Phase 6: Safely verify the candidate patch in isolation sandbox
        if response.patch:
            f = Finding.from_dict(finding)
            ver_result = verify_patch(project_root, response.patch, f)
            response.patch.verification_status = ver_result.status.value

            resp_dict = response.to_dict()
            resp_dict["patch"]["verification_details"] = ver_result.to_dict()
            return JSONResponse(content=resp_dict)

        return JSONResponse(content=response.to_dict())
    except Exception:
        log.exception(
            "Repair engine failed for session=%s rule=%s mode=%s",
            session_id, finding.get("rule_id"), mode
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "REPAIR_ENGINE_ERROR",
                    "message": "Repair engine encountered an unexpected error.",
                }
            },
        )
