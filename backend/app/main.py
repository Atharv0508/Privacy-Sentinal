from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .analyzer import analyze_scan
from .models import AnalysisResult, ReportListItem, ScanRequest
from .pdf_report import build_report_pdf

app = FastAPI(title="Privacy Sentinel API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORT_STORE: dict[str, AnalysisResult] = {}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "privacy-sentinel-api"}


@app.post("/analyze", response_model=AnalysisResult)
def analyze(scan: ScanRequest) -> AnalysisResult:
    report_id = str(uuid4())
    result = analyze_scan(scan, report_id=report_id)
    REPORT_STORE[report_id] = result
    return result


@app.get("/report/{report_id}", response_model=AnalysisResult)
def get_report(report_id: str) -> AnalysisResult:
    report = REPORT_STORE.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/report/{report_id}/pdf")
def get_report_pdf(report_id: str) -> StreamingResponse:
    report = REPORT_STORE.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_data = build_report_pdf(report)
    filename = f"privacy-sentinel-{report_id}.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(iter([pdf_data]), media_type="application/pdf", headers=headers)


@app.post("/report/pdf")
def build_report_pdf_from_payload(report: AnalysisResult) -> StreamingResponse:
    pdf_data = build_report_pdf(report)
    filename = f"privacy-sentinel-{report.report_id}.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(iter([pdf_data]), media_type="application/pdf", headers=headers)


@app.delete("/report/{report_id}", status_code=204)
def delete_report(report_id: str) -> Response:
    if report_id not in REPORT_STORE:
        raise HTTPException(status_code=404, detail="Report not found")
    del REPORT_STORE[report_id]
    return Response(status_code=204)


@app.get("/reports", response_model=list[ReportListItem])
def list_reports() -> list[ReportListItem]:
    items: list[ReportListItem] = []
    for report in REPORT_STORE.values():
        items.append(
            ReportListItem(
                report_id=report.report_id,
                url=report.url,
                scanned_at=report.scanned_at,
                risk_score=report.risk_score,
                severity=report.severity,
            )
        )

    items.sort(key=lambda x: x.scanned_at if isinstance(x.scanned_at, datetime) else datetime.min, reverse=True)
    return items
