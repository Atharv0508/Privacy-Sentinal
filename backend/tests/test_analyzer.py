from datetime import datetime, timedelta, timezone

from app.analyzer import analyze_scan
from app.models import CookieRecord, PagePrivacySignals, ScanRequest


def test_flags_tracking_cookie_as_higher_risk() -> None:
    now = datetime.now(timezone.utc)
    req = ScanRequest(
        url="https://example.com",
        scanned_at=now,
        cookies=[
            CookieRecord(
                name="_ga",
                domain=".doubleclick.net",
                secure=False,
                httpOnly=False,
                sameSite="None",
                session=False,
                expirationDate=(now + timedelta(days=365)).timestamp(),
            )
        ],
    )

    result = analyze_scan(req, report_id="r1")
    assert result.third_party_cookies == 1
    assert result.tracking_indicators == 1
    assert result.risk_score >= 60
    assert result.severity in {"high", "critical"}


def test_first_party_secure_cookie_is_lower_risk() -> None:
    now = datetime.now(timezone.utc)
    req = ScanRequest(
        url="https://example.com",
        scanned_at=now,
        cookies=[
            CookieRecord(
                name="session_id",
                domain="example.com",
                secure=True,
                httpOnly=True,
                sameSite="Lax",
                session=True,
            )
        ],
    )

    result = analyze_scan(req, report_id="r2")
    assert result.first_party_cookies == 1
    assert result.third_party_cookies == 0
    assert result.severity == "low"


def test_different_cookie_profiles_produce_different_scores() -> None:
    now = datetime.now(timezone.utc)

    low_risk = ScanRequest(
        url="https://docs.python.org",
        scanned_at=now,
        cookies=[
            CookieRecord(
                name="session",
                domain="docs.python.org",
                secure=True,
                httpOnly=True,
                sameSite="Lax",
                session=True,
            )
        ],
    )

    high_risk = ScanRequest(
        url="https://news.example",
        scanned_at=now,
        cookies=[
            CookieRecord(
                name="_ga",
                domain=".doubleclick.net",
                secure=False,
                httpOnly=False,
                sameSite="None",
                session=False,
                expirationDate=(now + timedelta(days=365)).timestamp(),
            ),
            CookieRecord(
                name="ad_campaign",
                domain=".ads.tracker.net",
                secure=False,
                httpOnly=False,
                sameSite="",
                session=False,
                expirationDate=(now + timedelta(days=300)).timestamp(),
            ),
        ],
    )

    low = analyze_scan(low_risk, report_id="low")
    high = analyze_scan(high_risk, report_id="high")
    assert high.risk_score > low.risk_score
    assert high.severity in {"high", "critical"}


def test_recommendations_include_history_relevant_advice() -> None:
    now = datetime.now(timezone.utc)
    req = ScanRequest(
        url="https://example.com",
        scanned_at=now,
        recent_reports=[
            {
                "url": "https://example.com",
                "risk_score": 30,
                "severity": "medium",
                "tracking_indicators": 1,
                "third_party_cookies": 1,
                "insecure_cookies": 1,
                "recommendations": ["Use tracker-blocking extensions and deny unnecessary consent categories."],
            },
            {
                "url": "https://another-site.com",
                "risk_score": 20,
                "severity": "low",
                "tracking_indicators": 0,
                "third_party_cookies": 0,
                "insecure_cookies": 0,
                "recommendations": ["Current cookie profile looks relatively privacy-preserving; keep monitoring periodically."],
            },
        ],
        cookies=[
            CookieRecord(
                name="_ga",
                domain=".doubleclick.net",
                secure=False,
                httpOnly=False,
                sameSite="None",
                session=False,
                expirationDate=(now + timedelta(days=365)).timestamp(),
            )
        ],
    )

    result = analyze_scan(req, report_id="r3")
    joined = " ".join(result.recommendations).lower()
    assert "rising" in joined or "baseline" in joined or "high-risk" in joined


def test_page_signals_raise_risk_and_surface_alerts() -> None:
    now = datetime.now(timezone.utc)
    req = ScanRequest(
        url="https://video.example.com",
        scanned_at=now,
        page_signals=PagePrivacySignals(
            microphone=True,
            camera=True,
            location=True,
            third_party_data_alert=True,
            third_party_endpoints=["https://analytics.example.net/collect"],
        ),
        cookies=[
            CookieRecord(
                name="session_id",
                domain="video.example.com",
                secure=True,
                httpOnly=True,
                sameSite="Lax",
                session=True,
            )
        ],
    )

    result = analyze_scan(req, report_id="r4")
    assert result.page_signals.microphone is True
    assert result.page_signals.camera is True
    assert result.page_signals.location is True
    assert result.page_signals.third_party_data_alert is True
    assert result.risk_score >= 40
    joined = " ".join(result.recommendations).lower()
    assert "third-party endpoints" in joined or "sending data" in joined
