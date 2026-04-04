from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import REPORT_STORE, app
from app.models import AnalysisResult, PagePrivacySignals


def test_report_pdf_endpoint_returns_readable_pdf() -> None:
    report_id = "pdf-test-1"
    REPORT_STORE[report_id] = AnalysisResult(
        report_id=report_id,
        url="https://example.com",
        scanned_at=datetime.now(timezone.utc),
        total_cookies=3,
        first_party_cookies=2,
        third_party_cookies=1,
        tracking_indicators=1,
        insecure_cookies=1,
        risk_score=48,
        severity="medium",
        recommendations=["Review and clear third-party cookies regularly."],
        findings=[],
        page_signals=PagePrivacySignals(),
    )

    client = TestClient(app)
    response = client.get(f"/report/{report_id}/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert "attachment;" in response.headers.get("content-disposition", "")
    assert response.content.startswith(b"%PDF")

    del REPORT_STORE[report_id]


def test_report_pdf_from_payload_endpoint_returns_pdf() -> None:
    client = TestClient(app)
    payload = {
        "report_id": "pdf-payload-1",
        "url": "https://example.org",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total_cookies": 4,
        "first_party_cookies": 3,
        "third_party_cookies": 1,
        "tracking_indicators": 1,
        "insecure_cookies": 1,
        "risk_score": 52,
        "severity": "medium",
        "recommendations": ["Audit trackers and clear old cookies."],
        "findings": [],
        "page_signals": {
            "microphone": False,
            "camera": False,
            "location": False,
            "third_party_data_alert": False,
            "third_party_endpoints": [],
            "evidence": [],
        },
    }

    response = client.post("/report/pdf", json=payload)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF")