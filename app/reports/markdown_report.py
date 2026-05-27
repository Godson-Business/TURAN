from __future__ import annotations

from pathlib import Path

from app.models import ScanResult


def _append_context_block(lines: list[str], result: ScanResult) -> None:
    if result.context is None:
        return

    discovery = result.context.discovery
    lines.extend(
        [
            "",
            "## Application Context",
            "",
            f"- Root: {result.context.root}",
            f"- Target: {result.context.target.value if result.context.target else 'not resolved'}",
            f"- Target source: {result.context.target.source if result.context.target else 'not resolved'}",
            f"- Discovered app: {discovery.app_name or '-'}",
            f"- Public URL: {discovery.public_url or '-'}",
            f"- Local URL: {discovery.local_url or '-'}",
            f"- Env file: {discovery.env_file or '-'}",
            f"- Env source: {discovery.env_source or '-'}",
            f"- Nginx config: {discovery.nginx_config or '-'}",
            f"- Systemd service: {discovery.systemd_service or '-'}",
        ]
    )
    if discovery.notes:
        lines.append(f"- Notes: {'; '.join(discovery.notes)}")


def write_markdown_report(result: ScanResult, output_path: str | Path, include_fix_plans: bool = False) -> Path:
    path = Path(output_path)
    lines = [
        "# Turan Report",
        "",
        f"Target: {result.target.url}",
        f"Findings: {len(result.findings)}",
    ]
    _append_context_block(lines, result)
    if result.tls_summary:
        lines.extend(
            [
                "",
                "## TLS",
                "",
                f"Status: {result.tls_summary.get('status', 'unknown')}",
            ]
        )
        if result.tls_summary.get("expires_on"):
            lines.append(f"Expires on: {result.tls_summary['expires_on']}")
    if include_fix_plans and result.fix_plans:
        lines.extend(["", "## Proposed Fixes", ""])
        for plan in result.fix_plans:
            lines.append(f"- {plan.expected_impact}")
            if plan.rollback_command:
                lines.append(f"  - Rollback: {plan.rollback_command}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
