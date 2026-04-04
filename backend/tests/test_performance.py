from datetime import datetime, timedelta, timezone
from time import perf_counter

from app.analyzer import analyze_scan
from app.models import CookieRecord, ScanRequest


def _build_cookie(i: int, now: datetime) -> CookieRecord:
    return CookieRecord(
        name=f"cookie_{i}_ga" if i % 3 == 0 else f"cookie_{i}",
        domain=".doubleclick.net" if i % 4 == 0 else "example.com",
        secure=(i % 2 == 0),
        httpOnly=(i % 5 != 0),
        sameSite="None" if i % 6 == 0 else "Lax",
        session=(i % 7 == 0),
        expirationDate=(now + timedelta(days=(30 + i))).timestamp(),
    )


def test_analyzer_performance_under_batch_load() -> None:
    now = datetime.now(timezone.utc)
    scans = []
    for idx in range(350):
        scans.append(
            ScanRequest(
                url=f"https://site-{idx % 10}.example.com",
                scanned_at=now,
                cookies=[_build_cookie(i, now) for i in range(25)],
            )
        )

    start = perf_counter()
    for idx, scan in enumerate(scans):
        analyze_scan(scan, report_id=f"p-{idx}")
    elapsed = perf_counter() - start

    # Keeps baseline performance visible while avoiding flaky thresholds on slower machines.
    assert elapsed < 2.2
