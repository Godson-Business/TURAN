from __future__ import annotations

from pathlib import Path

from app.artifacts import load_scan_result
from app.models import ComparisonFinding, ComparisonResult, ScanResult

_RISK_WEIGHTS = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 5,
    "critical": 8,
}


def score_findings(result: ScanResult) -> int:
    return sum(_RISK_WEIGHTS.get(finding.severity, 0) for finding in result.findings)


def summarize_comparison(comparison: ComparisonResult) -> str:
    if comparison.risk_trend == "improved":
        trend_text = "risk score improved"
    elif comparison.risk_trend == "worsened":
        trend_text = "risk score worsened"
    else:
        trend_text = "risk score stayed the same"
    context_text = f"; {len(comparison.context_changes)} context change(s)." if comparison.context_changes else ""
    return (
        f"{trend_text} ({comparison.old_risk_score} -> {comparison.new_risk_score}); "
        f"{len(comparison.fixed_findings)} fixed, {len(comparison.new_findings)} new."
        f"{context_text}"
    )


def _context_summary(result: ScanResult) -> str:
    if result.context is None:
        return "context not captured"

    discovery = result.context.discovery
    target = result.context.target.value if result.context.target is not None else "not resolved"
    pieces = [f"target={target}"]
    if discovery.app_name:
        pieces.append(f"app={discovery.app_name}")
    if discovery.public_url:
        pieces.append(f"public={discovery.public_url}")
    if discovery.local_url:
        pieces.append(f"local={discovery.local_url}")
    return ", ".join(pieces)


def compare_contexts(old_result: ScanResult, new_result: ScanResult) -> list[str]:
    changes: list[str] = []
    old_context = old_result.context
    new_context = new_result.context

    if old_context is None and new_context is None:
        return changes

    old_summary = _context_summary(old_result)
    new_summary = _context_summary(new_result)
    if old_summary != new_summary:
        changes.append(f"context changed: {old_summary} -> {new_summary}")

    if old_context is None and new_context is not None:
        changes.append("new discovery context was captured")
    elif old_context is not None and new_context is None:
        changes.append("old discovery context is missing from the new report")

    return changes


def compare_scan_results(old_result: ScanResult, new_result: ScanResult, old_report: str, new_report: str) -> ComparisonResult:
    old_by_id = {finding.id: finding for finding in old_result.findings}
    new_by_id = {finding.id: finding for finding in new_result.findings}

    fixed_findings = [
        ComparisonFinding(
            finding_id=finding.id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            change="fixed",
        )
        for finding_id, finding in old_by_id.items()
        if finding_id not in new_by_id
    ]
    new_findings = [
        ComparisonFinding(
            finding_id=finding.id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            change="new",
        )
        for finding_id, finding in new_by_id.items()
        if finding_id not in old_by_id
    ]
    unchanged_findings = [
        ComparisonFinding(
            finding_id=finding.id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            change="unchanged",
        )
        for finding_id, finding in new_by_id.items()
        if finding_id in old_by_id
    ]

    old_score = score_findings(old_result)
    new_score = score_findings(new_result)
    if new_score < old_score:
        trend = "improved"
    elif new_score > old_score:
        trend = "worsened"
    else:
        trend = "unchanged"

    return ComparisonResult(
        old_report=old_report,
        new_report=new_report,
        old_context=old_result.context,
        new_context=new_result.context,
        context_changes=compare_contexts(old_result, new_result),
        fixed_findings=fixed_findings,
        new_findings=new_findings,
        unchanged_findings=unchanged_findings,
        old_risk_score=old_score,
        new_risk_score=new_score,
        risk_trend=trend,
    )


def compare_scan_files(old_report: str | Path, new_report: str | Path) -> ComparisonResult:
    old_path = Path(old_report)
    new_path = Path(new_report)
    return compare_scan_results(
        load_scan_result(old_path),
        load_scan_result(new_path),
        str(old_path),
        str(new_path),
    )
