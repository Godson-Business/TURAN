# Turan

Turan is a Python-based web security scanner and hardening assistant.

## Status

Active CLI slice with scan, report, baseline, compare, audit, doctor, server-check, fix, and demo-site commands.

## Commands

- `scan` scans a live target, or falls back to `APP_URL` / `TARGET_URL` / `BASE_URL` in `.env` or `--env-file`, then discovers a local app target when needed
- `report` re-renders or previews a saved scan report
- `audit` shows the append-only audit history
- `baseline` saves a scan snapshot for later comparison
- `compare` shows what changed between two saved scans
- `doctor` checks the local machine and app environment
- `server-check` checks the server-facing config, discovers the app target, and scans it locally
- `fix` applies the first real local fix lane with `--local`
- `demo-site` starts the local test site

## Run

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com
```

If you want Turan to discover the app target on a VPS, you can leave the URL off:

```powershell
.\venv\Scripts\python.exe -m app.main scan
```

Turan looks for `APP_URL`, then `TARGET_URL`, then `BASE_URL`.

If those are missing, Turan checks the server layout first and prefers the app's own `.env` when Nginx or systemd point to an app root or an explicit `EnvironmentFile`.

If discovery still can't resolve a target, Turan falls back to the project `.env` only as the last local fallback.

When that happens, Turan prints a short `Discovery:` line first and then the fuller context block.

You can also point Turan at a specific env file:

```powershell
.\venv\Scripts\python.exe -m app.main scan --env-file C:\path\to\autoentrytrack\.env
```

## `.env` variables

| Variable | Used by | Meaning |
| --- | --- | --- |
| `APP_URL` | `scan` | Default target URL when you skip the argument |
| `TARGET_URL` | `scan` | Backup target URL if `APP_URL` is missing |
| `BASE_URL` | `scan` | Final fallback target URL |
| `DEBUG` | `doctor`, `server-check` | Flags a noisy local debug setup |
| `SECRET_KEY` | `doctor`, `server-check` | Checked for presence and weak values only |
| `SERVER_NAME` | `doctor`, `server-check` | Reported as present or missing |
| `DATABASE_URL` | `doctor`, `server-check` | Reported as present or missing |
| `SMTP_PASSWORD` | `doctor`, `server-check` | Reported as present or missing |

## Local file overrides

```powershell
.\venv\Scripts\python.exe -m app.main doctor --env-file C:\path\to\autoentrytrack\.env
.\venv\Scripts\python.exe -m app.main server-check --env-file C:\path\to\autoentrytrack\.env --nginx-config /etc/nginx/nginx.conf
```

## Export reports

Turan writes three report formats:

- `--json-output` for machine-readable data
- `--markdown-output` for a quick human-readable report
- `--html-output` for the polished browser version

When Turan discovers a local app target, the saved JSON, Markdown, and HTML reports include an `Application Context` section with the resolved target, env source, server hints, and discovery notes.

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --json-output reports\scan.json --markdown-output reports\scan.md
```

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --html-output reports\scan.html
```

Turan can write JSON, Markdown, and HTML reports in the same scan run if you pass the output paths you want.

## Re-render a saved report

```powershell
.\venv\Scripts\python.exe -m app.main report reports\scan.json --html-output reports\scan.html
```

`report` accepts `.json`, `.md`, and `.html` files.

```powershell
.\venv\Scripts\python.exe -m app.main report reports\scan.md
.\venv\Scripts\python.exe -m app.main report reports\scan.html
```

## Save a baseline

```powershell
.\venv\Scripts\python.exe -m app.main baseline https://example.com --output baselines\example.json
```

You can give the baseline a friendlier name too:

```powershell
.\venv\Scripts\python.exe -m app.main baseline https://example.com --label vps-west
```

Turan also writes a small companion metadata file next to each baseline snapshot, like `baselines\vps-west.json.meta.json`, so you can see the resolved target and discovery trail later.

You can point the audit log at a different file too:

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --audit-log logs\audit.log
.\venv\Scripts\python.exe -m app.main baseline https://example.com --audit-log logs\audit.log
```

## Compare two scans

```powershell
.\venv\Scripts\python.exe -m app.main compare reports\old.json reports\new.json
```

You can also write a Markdown or HTML diff report:

```powershell
.\venv\Scripts\python.exe -m app.main compare old.json new.json --markdown-output compare.md
.\venv\Scripts\python.exe -m app.main compare old.json new.json --html-output compare.html
```

## Audit history

```powershell
.\venv\Scripts\python.exe -m app.main audit --last 25
.\venv\Scripts\python.exe -m app.main audit --event scan
.\venv\Scripts\python.exe -m app.main audit --target example.com
.\venv\Scripts\python.exe -m app.main audit --audit-log reports\audit.log
.\venv\Scripts\python.exe -m app.main audit --json-output reports\audit.json
```

## Doctor

```powershell
.\venv\Scripts\python.exe -m app.main doctor
```

`doctor` checks the local machine, config paths, open localhost ports, safe environment status, and any resolved app target without taking a target URL.

## Server check

```powershell
.\venv\Scripts\python.exe -m app.main server-check
```

`server-check` stays focused on server-facing paths, local service signals, and config checks, then scans the resolved local target when one is found.

## Timeout

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --timeout 5
```

## Policy file

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --policy policy.json
```

Copy [policy.example.json](policy.example.json) to `policy.json` and adjust the values for your environment.

## Preview fixes

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --preview-fixes
```

## Interactive fixes

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --interactive
```

Turan shows a numbered list of suggested fixes, asks whether you want to generate artifacts or apply fixes locally, and then lets you choose all fixes or just the ones you want by number or range.
For `fix-local`, Turan shows the target file, backup path, validation command, and rollback state before the final apply confirmation.

## Apply fixes

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --generate-fixes
```

`--generate-fixes` creates a backup first, then writes local remediation notes for allowed safe changes. It does not change system services or config outside the approved gate.
`--apply-fixes` still works as a legacy alias for `--generate-fixes`, so older commands keep running while the wording stays honest.
Each remediation note includes the backup path when Turan creates one.
The generated fix artifact itself is written as a small artifact under `reports/generated/`.

Turan also appends scan and fix events to `reports/audit.log` by default.

## Real local fix

```powershell
.\venv\Scripts\python.exe -m app.main fix --local
```

`fix --local` is the first real live-edit lane. It discovers a supported server file, creates a backup of the real file first, applies one small reversible edit, validates the config, and rolls back if validation fails.

## Local Demo Site

Start the demo site in one terminal:

```powershell
.\venv\Scripts\python.exe -m app.main demo-site --port 8000
```

Then scan it from another terminal:

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000
```
