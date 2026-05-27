from __future__ import annotations

import typer
from rich.console import Console

from app.models import FixPlan, ScanResult


_prompt_console = Console()


def approve(plan: FixPlan, approver: str) -> FixPlan:
    return plan.model_copy(
        update={
            "status": "approved",
            "approved_by": approver,
        }
    )


def ask_to_create_backup() -> bool:
    return typer.confirm("Create backup first?", default=True)


def ask_to_apply_local_fix() -> bool:
    return typer.confirm("Apply selected local fixes?", default=False)


def choose_interactive_fix_mode() -> str:
    _prompt_console.print("Choose action:")
    _prompt_console.print("  [1] Generate fix artifacts only")
    _prompt_console.print("  [2] Apply fixes locally")
    _prompt_console.print("  [3] Skip")
    while True:
        choice = typer.prompt("Action", default="1").strip().lower()
        if choice in {"1", "generate", "g"}:
            return "generate"
        if choice in {"2", "local", "fix", "apply"}:
            return "local"
        if choice in {"3", "skip", "none"}:
            return "skip"
        _prompt_console.print("Pick 1, 2, or 3.")


def choose_interactive_fix_selection(result: ScanResult) -> str:
    _prompt_console.print("Select fixes:")
    _prompt_console.print("  all")
    _prompt_console.print("  1,2,4")
    _prompt_console.print("  3-7")
    _prompt_console.print("  none")
    max_number = len(result.fix_plans)
    return typer.prompt(f"Choose fixes [1-{max_number}]", default="all").strip()
