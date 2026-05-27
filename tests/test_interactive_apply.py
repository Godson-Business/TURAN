from pathlib import Path

from app import main
from app.config import AppConfig
from app.context import ApplicationContext, DiscoveryReport
from app.environment import ResolvedScanTarget
from app.models import Finding, FixPlan, ScanResult, Target


def build_generate_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        findings=[
            Finding(
                id="f1",
                target_url="https://example.com",
                title="Weak cookie flags",
                description="A cookie is missing Secure or HttpOnly.",
                severity="low",
                category="cookies",
                fix_level=0,
                risk_level="low",
                expected_impact="Report only.",
            )
        ],
        fix_plans=[
            FixPlan(
                finding_id="f1",
                fix_level=0,
                risk_level="low",
                rollback_command="Delete the note file.",
                expected_impact="Set Secure and HttpOnly where the cookie is issued first.",
            )
        ],
    )


def build_local_result(nginx_config: Path) -> ScanResult:
    context = ApplicationContext(
        root="/srv/turan",
        target=ResolvedScanTarget(value="http://127.0.0.1:8000", source="discovery", key="discovered"),
        discovery=DiscoveryReport(
            discovered=True,
            app_name="AutoEntryTrack",
            target_url="http://127.0.0.1:8000",
            local_url="http://127.0.0.1:8000",
            nginx_config=str(nginx_config),
        ),
    )
    return ScanResult(
        target=Target(url="http://127.0.0.1:8000", scheme="http", host="127.0.0.1"),
        context=context,
        findings=[
            Finding(
                id="server-info-1",
                target_url="http://127.0.0.1:8000",
                title="Server information disclosure",
                description="The banner is exposed.",
                severity="low",
                category="server_info",
                fix_level=1,
                risk_level="low",
                expected_impact="Hide the banner in the web server config first.",
            )
        ],
        fix_plans=[
            FixPlan(
                finding_id="server-info-1",
                fix_level=1,
                risk_level="low",
                rollback_command="Restore the previous web server config.",
                expected_impact="Hide the banner in the web server config first.",
            )
        ],
    )


def test_interactive_scan_generates_selected_fix_artifacts(monkeypatch) -> None:
    calls = []
    decisions_seen = []
    events = []

    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(allowed_fix_level=0))
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: build_generate_result())
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(main, "render_interactive_fix_catalog", lambda result: "catalog")
    monkeypatch.setattr(main, "choose_interactive_fix_mode", lambda: "generate")
    monkeypatch.setattr(main, "choose_interactive_fix_selection", lambda result: "1")
    monkeypatch.setattr(
        main,
        "render_fix_decisions",
        lambda decisions: decisions_seen.extend(decisions) or "decisions",
    )
    monkeypatch.setattr(
        main,
        "create_applied_artifact_backup",
        lambda finding, output_dir="reports/generated": events.append(("backup", finding.id)) or Path("reports/backups/f1.conf.bak"),
    )
    monkeypatch.setattr(
        main,
        "execute_fix",
        lambda finding, plan, policy, backup_path=None: events.append(("generate", finding.id)) or calls.append((finding.id, plan.finding_id)) or "generated",
    )

    main.scan("https://example.com", interactive=True)

    assert calls == [("f1", "f1")]
    assert events == [("backup", "f1"), ("generate", "f1")]
    assert decisions_seen[0].status == "generated"


def test_interactive_scan_skips_when_the_user_skips(monkeypatch) -> None:
    calls = []
    decisions_seen = []

    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(allowed_fix_level=0))
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: build_generate_result())
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(main, "render_interactive_fix_catalog", lambda result: "catalog")
    monkeypatch.setattr(main, "choose_interactive_fix_mode", lambda: "skip")
    monkeypatch.setattr(main, "choose_interactive_fix_selection", lambda result: "1")
    monkeypatch.setattr(
        main,
        "render_fix_decisions",
        lambda decisions: decisions_seen.extend(decisions) or "decisions",
    )
    monkeypatch.setattr(main, "create_applied_artifact_backup", lambda finding, output_dir="reports/generated": calls.append(("backup", finding.id)) or Path("reports/backups/f1.conf.bak"))
    monkeypatch.setattr(main, "execute_fix", lambda finding, plan, policy, backup_path=None: calls.append((finding.id, plan.finding_id)) or "generated")

    main.scan("https://example.com", interactive=True)

    assert calls == []
    assert decisions_seen == []


def test_interactive_scan_applies_a_selected_local_fix(monkeypatch, workspace_temp_dir) -> None:
    calls = []
    decisions_seen = []
    events = []
    messages = []

    class ConsoleRecorder:
        def print(self, *parts, **kwargs) -> None:
            messages.append(" ".join(str(part) for part in parts))

    monkeypatch.setattr(main, "console", ConsoleRecorder())
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(allowed_fix_level=1))
    nginx_config = workspace_temp_dir / "nginx.conf"
    nginx_config.write_text("server {\n    listen 80;\n}\n", encoding="utf-8")
    local_result = build_local_result(nginx_config)
    monkeypatch.setattr(main, "resolve_application_context", lambda url, root, env_file, require_target=True: local_result.context)
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: local_result)
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(main, "render_interactive_fix_catalog", lambda result: "catalog")
    monkeypatch.setattr(main, "render_local_fix_preview", lambda target_path, backup_path, validation_command, findings: "preview")
    monkeypatch.setattr(main, "choose_interactive_fix_mode", lambda: "local")
    monkeypatch.setattr(main, "choose_interactive_fix_selection", lambda result: "1")
    monkeypatch.setattr(main, "choose_local_fix_target", lambda result: nginx_config)
    monkeypatch.setattr(main, "ask_to_apply_local_fix", lambda: True)
    monkeypatch.setattr(
        main,
        "render_fix_decisions",
        lambda decisions: decisions_seen.extend(decisions) or "decisions",
    )
    monkeypatch.setattr(
        main,
        "create_backup",
        lambda target_path, output_dir: events.append(("backup", target_path.as_posix()))
        or target_path.parent / f"{target_path.name}.bak",
    )
    monkeypatch.setattr(
        main,
        "apply_local_nginx_hardening_fix",
        lambda target_path, categories=None, backup_path=None: events.append(("apply", target_path.as_posix()))
        or main.LocalFixResult(
            target_path=str(target_path),
            status="applied",
            reason="Inserted server_tokens off; and the validation check passed.",
            backup_path=str(backup_path or (target_path.parent / f"{target_path.name}.bak")),
            validation_command=f"nginx -t -c {target_path}",
            validation_output="syntax is ok",
            notes=["Reload the service when you are ready."],
        ),
    )
    monkeypatch.setattr(
        main,
        "append_audit_event",
        lambda path, event: events.append(("audit", event.action)),
    )

    main.scan(None, interactive=True)

    assert decisions_seen == []
    assert ("backup", nginx_config.as_posix()) in events
    assert ("apply", nginx_config.as_posix()) in events
    assert events[-1] == ("audit", "local_fix")


def test_apply_fixes_creates_a_backup_before_writing(monkeypatch) -> None:
    calls = []
    events = []
    decisions_seen = []
    messages = []

    class ConsoleRecorder:
        def print(self, *parts, **kwargs) -> None:
            messages.append(" ".join(str(part) for part in parts))

    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(allowed_fix_level=0))
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: build_generate_result())
    monkeypatch.setattr(main, "console", ConsoleRecorder())
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(
        main,
        "render_fix_decisions",
        lambda decisions: decisions_seen.extend(decisions) or "decisions",
    )
    monkeypatch.setattr(
        main,
        "create_applied_artifact_backup",
        lambda finding, output_dir="reports/generated": events.append(("backup", finding.id)) or Path("reports/backups/f1.conf.bak"),
    )
    monkeypatch.setattr(
        main,
        "execute_fix",
        lambda finding, plan, policy, backup_path=None: events.append(("generate", finding.id)) or calls.append((finding.id, plan.finding_id)) or "generated",
    )

    main.scan("https://example.com", generate_fixes=True)

    assert calls == [("f1", "f1")]
    assert events == [("backup", "f1"), ("generate", "f1")]
    assert decisions_seen[0].status == "generated"
    assert any(message.startswith("Generated artifact:") for message in messages)
