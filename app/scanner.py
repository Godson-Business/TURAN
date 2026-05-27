from __future__ import annotations

import httpx
from urllib.parse import urlparse

from app.checks.headers import check_security_headers
from app.checks.exposed_files import check_exposed_files
from app.checks.cookies import check_cookie_flags
from app.checks.server_info import extract_server_banner
from app.checks.waf import detect_waf_signals
from app.checks.tls import summarize_tls
from app.hardening.recommendations import recommend_fix
from app.http.client import build_client, fetch_page
from app.http.normalizer import normalize_url, same_host
from app.models import Finding, ScanResult, Target


def scan_target(target_url: str, timeout_seconds: float = 10.0) -> ScanResult:
    # Normalize the input.
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    canonical_url = normalize_url(f"{parsed.scheme}://{parsed.netloc or parsed.path}", parsed.path or "/")
    target = Target(url=canonical_url, scheme=parsed.scheme or "https", host=parsed.netloc or parsed.path)

    findings: list[Finding] = []
    notes: list[str] = []
    scanned_urls = [canonical_url]

    with build_client(timeout_seconds) as client:
        try:
            response = fetch_page(client, canonical_url)
        except httpx.RequestError as exc:
            notes.append(f"Request failed: {exc.__class__.__name__}")
            findings.append(
                Finding(
                    id="target-unreachable",
                    target_url=canonical_url,
                    title="Target unreachable",
                    description="Turan could not complete the initial request.",
                    severity="low",
                    category="connectivity",
                    evidence={
                        "error": exc.__class__.__name__,
                        "url": canonical_url,
                    },
                    fix_level=0,
                    risk_level="low",
                    expected_impact="Report only; no system change required.",
                    references=[],
                )
            )
            response = None

        if response is None:
            waf_signals = []
            tls_summary = {}
            fix_plans = [recommend_fix(finding) for finding in findings]
            return ScanResult(
                target=target,
                findings=findings,
                fix_plans=fix_plans,
                scanned_urls=scanned_urls,
                notes=notes,
                waf_signals=waf_signals,
                tls_summary=tls_summary,
                scan_confidence=0.0,
            )

        page_url = str(response.url)
        if not same_host(canonical_url, page_url):
            notes.append("Redirect moved the scan outside the original host.")

        missing_headers = check_security_headers(dict(response.headers))
        for header_name in missing_headers:
            findings.append(
                Finding(
                    id=f"missing-{header_name}",
                    target_url=page_url,
                    title=f"Missing security header: {header_name}",
                    description=f"The response does not include the {header_name} header.",
                    severity="low",
                    category="headers",
                    evidence={
                        "header": header_name,
                        "status_code": response.status_code,
                        "url": page_url,
                    },
                    fix_level=0,
                    risk_level="low",
                    expected_impact="Report only; no system change required.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
                )
            )

        weak_cookie_headers = check_cookie_flags(response.headers.get_list("set-cookie"))
        for cookie_header in weak_cookie_headers:
            findings.append(
                Finding(
                    id=f"weak-cookie-{len(findings)}",
                    target_url=page_url,
                    title="Weak cookie flags",
                    description="A cookie is missing Secure or HttpOnly.",
                    severity="low",
                    category="cookies",
                    evidence={
                        "set_cookie": cookie_header,
                        "status_code": response.status_code,
                        "url": page_url,
                    },
                    fix_level=0,
                    risk_level="low",
                    expected_impact="Report only; no system change required.",
                    references=["https://owasp.org/www-community/HttpOnly"],
                )
            )

        server_banner = extract_server_banner(dict(response.headers))
        if server_banner:
            findings.append(
                Finding(
                    id="server-banner-disclosure",
                    target_url=page_url,
                    title="Server information disclosure",
                    description="The response reveals a server banner or framework header.",
                    severity="low",
                    category="server_info",
                    evidence={
                        "header_value": server_banner,
                        "status_code": response.status_code,
                        "url": page_url,
                    },
                    fix_level=0,
                    risk_level="low",
                    expected_impact="Report only; no system change required.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                )
            )

        waf_signals = detect_waf_signals(dict(response.headers))
        notes.extend([f"WAF signal: {signal}" for signal in waf_signals])

        exposed_file_findings = check_exposed_files(client, canonical_url)
        findings.extend(exposed_file_findings)

    tls_summary = {}
    if target.scheme == "https":
        tls_summary = summarize_tls(str(target.url), timeout_seconds=timeout_seconds)
        if tls_summary.get("status") == "ok":
            days_left = tls_summary.get("days_left", "")
            if days_left.isdigit() and int(days_left) <= 30:
                findings.append(
                    Finding(
                        id="tls-certificate-expiry",
                        target_url=str(target.url),
                        title="TLS certificate expires soon",
                        description="The certificate has 30 days or less left.",
                        severity="medium",
                        category="tls",
                        evidence=tls_summary,
                        fix_level=0,
                        risk_level="low",
                        expected_impact="Report only; no system change required.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    )
                )

    fix_plans = [recommend_fix(finding) for finding in findings]
    return ScanResult(
        target=target,
        findings=findings,
        fix_plans=fix_plans,
        scanned_urls=scanned_urls,
        notes=notes,
        waf_signals=waf_signals,
        tls_summary=tls_summary,
        scan_confidence=1.0,
    )
