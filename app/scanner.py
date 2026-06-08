from __future__ import annotations

import httpx
from urllib.parse import urlparse

from app.checks.headers import check_security_headers
from app.checks.exposed_files import check_exposed_files
from app.checks.cookies import check_cookie_flags
from app.checks.server_info import extract_server_banner
from app.checks.waf import detect_waf_signals
from app.checks.tls import summarize_tls

from app.checks.xss_check import check_xss
from app.checks.sqli_check import check_sqli
from app.checks.ssti_check import check_ssti
from app.checks.traversal_check import check_directory_traversal

from app.checks.csrf_check import check_csrf
from app.checks.clickjacking_check import check_clickjacking
from app.checks.open_redirect_check import check_open_redirect
from app.checks.info_disclosure_check import check_information_disclosure

from app.hardening.recommendations import recommend_fix
from app.http.client import build_client, fetch_page
from app.http.normalizer import normalize_url, same_host
from app.models import Finding, ScanResult, Target


def scan_target(target_url: str, timeout_seconds: float = 10.0) -> ScanResult:
    """
    Main Turan scan engine.
    """

    parsed = urlparse(
        target_url if "://" in target_url else f"https://{target_url}"
    )

    canonical_url = normalize_url(
        f"{parsed.scheme}://{parsed.netloc or parsed.path}",
        parsed.path or "/",
    )

    target = Target(
        url=canonical_url,
        scheme=parsed.scheme or "https",
        host=parsed.netloc or parsed.path,
    )

    findings: list[Finding] = []
    notes: list[str] = []
    scanned_urls = [canonical_url]

    with build_client(timeout_seconds) as client:

        try:
            response = fetch_page(client, canonical_url)

        except httpx.RequestError as exc:

            notes.append(
                f"Request failed: {exc.__class__.__name__}"
            )

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

            return ScanResult(
                target=target,
                findings=findings,
                fix_plans=[recommend_fix(f) for f in findings],
                scanned_urls=scanned_urls,
                notes=notes,
                waf_signals=[],
                tls_summary={},
                scan_confidence=0.0,
            )

        page_url = str(response.url)

        if not same_host(canonical_url, page_url):
            notes.append(
                "Redirect moved the scan outside the original host."
            )

        # Security Headers
        missing_headers = check_security_headers(
            dict(response.headers)
        )

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
                    references=[],
                )
            )

        # Cookies
        weak_cookie_headers = check_cookie_flags(
            response.headers.get_list("set-cookie")
        )

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
                    references=[],
                )
            )

        # Server Banner
        server_banner = extract_server_banner(
            dict(response.headers)
        )

        if server_banner:
            findings.append(
                Finding(
                    id="server-banner-disclosure",
                    target_url=page_url,
                    title="Server information disclosure",
                    description="The response reveals server or framework information.",
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
                    references=[],
                )
            )

        # WAF Detection
        waf_signals = detect_waf_signals(
            dict(response.headers)
        )

        notes.extend(
            [f"WAF signal: {signal}" for signal in waf_signals]
        )

        # Exposed Files
        findings.extend(
            check_exposed_files(
                client,
                canonical_url,
            )
        )

        # Vulnerability Checks
        findings.extend(check_xss(response))
        findings.extend(check_sqli(response))
        findings.extend(check_ssti(response))
        findings.extend(check_directory_traversal(response))
        findings.extend(check_csrf(response))
        findings.extend(check_clickjacking(response))
        findings.extend(check_open_redirect(response))
        findings.extend(check_information_disclosure(response))

        # TLS Checks
        tls_summary = {}

        if target.scheme == "https":

            tls_summary = summarize_tls(
                str(target.url),
                timeout_seconds=timeout_seconds,
            )

            if tls_summary.get("status") == "ok":

                days_left = str(
                    tls_summary.get("days_left", "")
                )

                if days_left.isdigit() and int(days_left) <= 30:

                    findings.append(
                        Finding(
                            id="tls-certificate-expiry",
                            target_url=str(target.url),
                            title="TLS certificate expires soon",
                            description="The certificate has 30 days or less remaining.",
                            severity="medium",
                            category="tls",
                            evidence=tls_summary,
                            fix_level=0,
                            risk_level="low",
                            expected_impact="Report only; no system change required.",
                            references=[],
                        )
                    )

        fix_plans = [
            recommend_fix(finding)
            for finding in findings
        ]

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