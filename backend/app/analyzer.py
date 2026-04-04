from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse
from .models import AnalysisResult, CookieRecord, CookieRiskFinding, PagePrivacySignals, RecentReportSnapshot, ScanRequest

TRACKER_DOMAIN_KEYWORDS = {
    "doubleclick",
    "adservice",
    "googlesyndication",
    "scorecardresearch",
    "facebook",
    "analytics",
    "segment",
    "hotjar",
    "mixpanel",
}

TRACKER_COOKIE_KEYWORDS = {
    "_ga",
    "_gid",
    "_fbp",
    "track",
    "pixel",
    "ad",
    "campaign",
    "analytics",
}


def _normalize_host(value: str) -> str:
    return value.lstrip(".").lower()


def _get_hostname(url: str) -> str:
    parsed = urlparse(url)
    return _normalize_host(parsed.hostname or "")


def _is_third_party(site_host: str, cookie_domain: str) -> bool:
    domain = _normalize_host(cookie_domain)
    if not domain or not site_host:
        return False
    if domain == site_host:
        return False
    return not site_host.endswith(f".{domain}") and not domain.endswith(f".{site_host}")


def _contains_tracker_keyword(text: str, keywords: set[str]) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def _cookie_age_days(cookie: CookieRecord, scanned_at: datetime) -> int:
    if cookie.expirationDate is None or cookie.session:
        return 0
    expiry = datetime.fromtimestamp(cookie.expirationDate, tz=timezone.utc)
    scan_utc = scanned_at.astimezone(timezone.utc) if scanned_at.tzinfo else scanned_at.replace(tzinfo=timezone.utc)
    diff = expiry - scan_utc
    return max(diff.days, 0)


def analyze_scan(scan: ScanRequest, report_id: str) -> AnalysisResult:
    site_host = _get_hostname(scan.url)
    page_signals = scan.page_signals
    first_party = 0
    third_party = 0
    tracking_indicators = 0
    insecure = 0
    total_score = 0
    findings: list[CookieRiskFinding] = []
    page_signal_score = 0

    if page_signals.microphone:
        page_signal_score += 14
        findings.append(
            CookieRiskFinding(
                cookie_name="page",
                domain=site_host or scan.url,
                risk_level="medium",
                reasons=["microphone access detected"],
            )
        )

    if page_signals.camera:
        page_signal_score += 14
        findings.append(
            CookieRiskFinding(
                cookie_name="page",
                domain=site_host or scan.url,
                risk_level="medium",
                reasons=["camera access detected"],
            )
        )

    if page_signals.location:
        page_signal_score += 12
        findings.append(
            CookieRiskFinding(
                cookie_name="page",
                domain=site_host or scan.url,
                risk_level="medium",
                reasons=["location access detected"],
            )
        )

    if page_signals.third_party_data_alert:
        page_signal_score += 22
        findings.append(
            CookieRiskFinding(
                cookie_name="network",
                domain=site_host or scan.url,
                risk_level="high",
                reasons=["third-party data transfer detected"],
            )
        )

    if page_signals.third_party_endpoints:
        page_signal_score += min(len(page_signals.third_party_endpoints) * 4, 12)

    for cookie in scan.cookies:
        reasons: list[str] = []
        score = 0
        is_third_party = _is_third_party(site_host, cookie.domain)

        if is_third_party:
            third_party += 1
            reasons.append("third-party cookie")
            score += 20
        else:
            first_party += 1

        if not cookie.secure:
            insecure += 1
            reasons.append("missing Secure flag")
            score += 10

        if not cookie.httpOnly:
            reasons.append("missing HttpOnly flag")
            score += 8

        if str(cookie.sameSite).lower() in {"none", "unspecified", ""}:
            reasons.append("weak SameSite policy")
            score += 8

        if _contains_tracker_keyword(cookie.domain, TRACKER_DOMAIN_KEYWORDS) or _contains_tracker_keyword(
            cookie.name, TRACKER_COOKIE_KEYWORDS
        ):
            tracking_indicators += 1
            reasons.append("tracking pattern detected")
            score += 18

        if _cookie_age_days(cookie, scan.scanned_at) >= 180:
            reasons.append("long persistence (>=180 days)")
            score += 10

        risk_level = "low"
        if score >= 45:
            risk_level = "high"
        elif score >= 25:
            risk_level = "medium"

        if reasons:
            findings.append(
                CookieRiskFinding(
                    cookie_name=cookie.name,
                    domain=cookie.domain,
                    risk_level=risk_level,
                    reasons=reasons,
                )
            )

        total_score += min(score, 60)

    total_cookies = len(scan.cookies)
    if total_cookies == 0:
        risk_score = 0
    else:
        unique_domains = len({_normalize_host(c.domain) for c in scan.cookies if c.domain})
        avg_cookie_score = total_score / total_cookies
        cookie_component = min(int(avg_cookie_score * 1.15 + total_cookies * 1.25), 68)
        third_party_component = min(int((third_party / total_cookies) * 24), 24)
        tracking_component = min(int((tracking_indicators / total_cookies) * 20), 20)
        insecure_component = min(int((insecure / total_cookies) * 14), 14)
        diversity_component = min(max(0, (unique_domains - 2) * 2), 10)
        risk_score = min(
            cookie_component
            + third_party_component
            + tracking_component
            + insecure_component
            + diversity_component,
            100,
        )

    risk_score = min(risk_score + min(page_signal_score, 40), 100)

    if risk_score >= 80:
        severity = "critical"
    elif risk_score >= 60:
        severity = "high"
    elif risk_score >= 35:
        severity = "medium"
    else:
        severity = "low"

    recommendations = _build_recommendations(
        site_host=site_host,
        risk_score=risk_score,
        severity=severity,
        third_party_count=third_party,
        insecure_count=insecure,
        tracking_count=tracking_indicators,
        cookies=scan.cookies,
        recent_reports=scan.recent_reports,
        page_signals=page_signals,
    )

    return AnalysisResult(
        report_id=report_id,
        url=scan.url,
        scanned_at=scan.scanned_at,
        total_cookies=total_cookies,
        first_party_cookies=first_party,
        third_party_cookies=third_party,
        tracking_indicators=tracking_indicators,
        insecure_cookies=insecure,
        risk_score=risk_score,
        severity=severity,
        recommendations=recommendations,
        findings=findings,
        page_signals=page_signals,
    )


def _build_recommendations(
    site_host: str,
    risk_score: int,
    severity: str,
    third_party_count: int,
    insecure_count: int,
    tracking_count: int,
    cookies: list[CookieRecord],
    recent_reports: list[RecentReportSnapshot],
    page_signals: PagePrivacySignals,
) -> list[str]:
    recommendations: list[str] = []
    used_recent_recommendations = {
        rec.strip().lower()
        for report in recent_reports
        for rec in report.recommendations
        if rec and rec.strip()
    }

    def add_fresh(candidates: list[str]) -> None:
        for candidate in candidates:
            if candidate.lower() not in used_recent_recommendations and candidate not in recommendations:
                recommendations.append(candidate)
                return
        for candidate in candidates:
            if candidate not in recommendations:
                recommendations.append(candidate)
                return

    if third_party_count > 0:
        add_fresh(
            [
                "Enable strict third-party cookie blocking and periodically review per-site exceptions.",
                "Block or restrict third-party cookies using browser privacy controls.",
            ]
        )

    if tracking_count > 0:
        add_fresh(
            [
                "Decline optional analytics/advertising consent on this site and re-scan to verify reduction.",
                "Use tracker-blocking extensions and deny unnecessary consent categories.",
            ]
        )

    if page_signals.third_party_data_alert:
        add_fresh(
            [
                "This site is sending data to third-party endpoints; review trackers, embeds, and consent banners before signing in.",
                "Treat third-party data transfer as a higher-risk signal and limit account use on this site.",
            ]
        )

    if page_signals.microphone or page_signals.camera or page_signals.location:
        add_fresh(
            [
                "Review whether microphone, camera, or location access is truly required before granting permissions.",
                "Deny unused device permissions to reduce exposure of sensitive browser and device data.",
            ]
        )

    if insecure_count > 0:
        add_fresh(
            [
                "Avoid authenticating on this site from untrusted networks due to weaker cookie security attributes.",
                "Prefer websites enforcing Secure and HttpOnly attributes on cookies.",
            ]
        )

    long_lived = [c for c in cookies if c.expirationDate is not None and not c.session]
    if len(long_lived) > max(2, len(cookies) // 3):
        add_fresh(
            [
                "Set a recurring cookie cleanup schedule for long-lived identifiers.",
                "Clear persistent cookies periodically to reduce long-term tracking.",
            ]
        )

    host_history = [r for r in recent_reports if _get_hostname(r.url) == site_host]
    if host_history:
        avg_host_risk = sum(r.risk_score for r in host_history) / len(host_history)
        if risk_score >= avg_host_risk + 10:
            add_fresh(
                [
                    "This site's privacy risk is rising compared to your recent visits; consider temporary isolation in a private window.",
                ]
            )

    if recent_reports:
        avg_tracking = sum(r.tracking_indicators for r in recent_reports) / len(recent_reports)
        if tracking_count > avg_tracking + 1:
            add_fresh(
                [
                    "Tracking indicators on this site exceed your recent browsing baseline; avoid signing in with primary accounts.",
                ]
            )

    if severity in {"high", "critical"}:
        add_fresh(
            [
                "For high-risk sites, use container tabs or a separate browser profile to limit cross-site correlation.",
            ]
        )

    if not recommendations:
        add_fresh(
            [
                "Current cookie profile is comparatively low-risk; keep this site in your trusted baseline watchlist.",
                "Current cookie profile looks relatively privacy-preserving; keep monitoring periodically.",
            ]
        )

    return recommendations[:5]
