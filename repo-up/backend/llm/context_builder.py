"""
backend/llm/context_builder.py — Context extraction and evidence packaging.

Supports both:
- Method 3 (LLM-Based Repair): Minimal context (rule, CWE, description, redacted source snippet).
- Method 4 (Context-Aware Hybrid Repair): Context-enriched evidence combining
  AST-level definitions/imports, file-level dependency graphs, and runtime output.
"""

from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List, Optional

SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|token|password|secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{10,})["\']'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----'),
]


def redact_secrets(text: str) -> str:
    """Redacts common secret patterns from context before sending to LLM."""
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(r'[REDACTED_SECRET]', text)
    return text


def sanitize_runtime_output(raw_output: str, max_lines: int = 15) -> str:
    """Sanitize runtime/test output to avoid path or secret leakage."""
    if not raw_output:
        return "[No runtime output]"
    text = re.sub(r'(/home/[^\s:]+|C:\\[^\s:]+)', '[SYSTEM_PATH]', raw_output)
    text = redact_secrets(text)
    lines = text.strip().splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... [truncated {len(lines) - max_lines} lines]"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# AST Context Extraction
# ---------------------------------------------------------------------------

def extract_ast_context(file_path: str, source_text: str, line_num: int, language: str) -> Dict[str, Any]:
    """
    Extracts relevant imports and enclosing function/class definitions for the target line.
    """
    imports: List[str] = []
    enclosing_def: Optional[str] = None

    lines = source_text.splitlines()

    # Python AST extraction
    if language.lower() == "python":
        try:
            tree = ast.parse(source_text, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(f"import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    names = ", ".join(a.name for a in node.names)
                    imports.append(f"from {mod} import {names}")

                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start = getattr(node, "lineno", None)
                    end = getattr(node, "end_lineno", None)
                    if start and end and start <= line_num <= end:
                        kind = "Class" if isinstance(node, ast.ClassDef) else "Function"
                        enclosing_def = f"{kind} {node.name} (lines {start}-{end})"
        except Exception:
            pass

    # Generic regex fallback for other languages (JS/TS, Java, C++) or unparsable Python
    if not imports:
        for l in lines[:50]:
            trimmed = l.strip()
            if (
                trimmed.startswith("import ")
                or trimmed.startswith("from ")
                or trimmed.startswith("#include")
                or trimmed.startswith("package ")
            ):
                imports.append(trimmed)

    return {
        "imports": imports[:10],
        "enclosing_definition": enclosing_def,
    }


# ---------------------------------------------------------------------------
# Dependency Graph Context Extraction
# ---------------------------------------------------------------------------

def extract_graph_context(project_root: str, file_path: str, max_neighbor_lines: int = 20) -> Dict[str, Any]:
    """
    Extracts file-level import/dependency graph neighbors using Repo-Up graph_service.
    """
    dependencies: List[str] = []
    dependents: List[str] = []
    neighbor_excerpts: Dict[str, str] = {}

    norm_target = file_path.replace("\\", "/").lstrip("/")

    try:
        from services.graph_service import build_dependency_graph

        graph = build_dependency_graph(project_root)

        matched_node = None
        for node in graph.nodes:
            norm_node = node.replace("\\", "/").lstrip("/")
            if norm_node == norm_target or norm_node.endswith("/" + norm_target):
                matched_node = node
                break

        if matched_node:
            for succ in graph.successors(matched_node):
                dependencies.append(succ.replace("\\", "/"))
            for pred in graph.predecessors(matched_node):
                dependents.append(pred.replace("\\", "/"))

            # Capture a small snippet from the primary dependency if present
            for dep in dependencies[:2]:
                abs_dep = os.path.join(project_root, dep)
                if os.path.isfile(abs_dep):
                    try:
                        with open(abs_dep, "r", encoding="utf-8", errors="ignore") as df:
                            dep_lines = df.readlines()[:max_neighbor_lines]
                        neighbor_excerpts[dep] = redact_secrets("".join(dep_lines))
                    except Exception:
                        pass
    except Exception:
        pass

    return {
        "dependencies": dependencies[:8],
        "dependents": dependents[:8],
        "neighbor_excerpts": neighbor_excerpts,
    }


# ---------------------------------------------------------------------------
# Public Context Builders
# ---------------------------------------------------------------------------

def build_minimal_context(finding: dict, project_root: str) -> dict:
    """
    Method 3 (LLM-Based Repair): Minimal context baseline.
    Contains rule, CWE, description, and localized source snippet only.
    """
    context: Dict[str, Any] = {
        "mode": "llm_based",
        "rule": finding.get("rule_id", "UNKNOWN"),
        "cwe": finding.get("cwe", "None"),
        "message": finding.get("description", ""),
        "file": finding.get("file", ""),
        "line": finding.get("line", 1),
        "source_snippet": "",
    }

    file_path = finding.get("file")
    line_num = finding.get("line", 1)

    if file_path:
        if file_path.endswith('.env') or 'secret' in file_path.lower():
            context["source_snippet"] = "[File excluded for privacy]"
            return context

        full_path = os.path.join(project_root, file_path)
        if os.path.abspath(full_path).startswith(os.path.abspath(project_root)):
            if os.path.isfile(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    start = max(0, line_num - 1 - 15)
                    end = min(len(lines), line_num - 1 + 15)
                    snippet = "".join(lines[start:end])
                    context["source_snippet"] = redact_secrets(snippet)
                except Exception:
                    pass

    return context


def build_hybrid_context(
    finding: dict,
    project_root: str,
    runtime_output: Optional[str] = None,
) -> dict:
    """
    Method 4 (Context-Aware Hybrid Repair): Context-enriched evidence.
    Enriches minimal context with AST structures, file-level dependency graph,
    and optional sanitized runtime/validator output.
    """
    context = build_minimal_context(finding, project_root)
    context["mode"] = "context_aware_hybrid"

    file_path = finding.get("file", "")
    line_num = finding.get("line", 1)
    language = finding.get("language", "")

    full_path = os.path.join(project_root, file_path)
    source_text = ""
    if os.path.isfile(full_path):
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_text = f.read()
        except Exception:
            pass

    # 1. AST Context
    ast_ctx = extract_ast_context(file_path, source_text, line_num, language)
    context["ast_context"] = ast_ctx

    # 2. Dependency Graph Context
    graph_ctx = extract_graph_context(project_root, file_path)
    context["graph_context"] = graph_ctx

    # 3. Runtime Evidence (if provided)
    if runtime_output:
        context["runtime_evidence"] = sanitize_runtime_output(runtime_output)

    return context


def build_context(
    finding: dict,
    project_root: str,
    mode: str = "context_aware_hybrid",
    runtime_output: Optional[str] = None,
) -> dict:
    """
    Unified context builder dispatcher.
    Supports mode='llm_based' or mode='context_aware_hybrid'.
    """
    if mode == "llm_based":
        return build_minimal_context(finding, project_root)
    return build_hybrid_context(finding, project_root, runtime_output=runtime_output)
