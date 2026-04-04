from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class CookieRecord(BaseModel):
    name: str
    value: Optional[str] = ""
    domain: str
    path: str = "/"
    secure: bool = False
    httpOnly: bool = False
    sameSite: str = "unspecified"
    session: bool = False
    expirationDate: Optional[float] = None


class PagePrivacySignals(BaseModel):
    microphone: bool = False
    camera: bool = False
    location: bool = False
    third_party_data_alert: bool = False
    third_party_endpoints: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    url: str
    cookies: List[CookieRecord] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    recent_reports: List["RecentReportSnapshot"] = Field(default_factory=list)
    page_signals: PagePrivacySignals = Field(default_factory=PagePrivacySignals)


class RecentReportSnapshot(BaseModel):
    url: str
    risk_score: int = 0
    severity: str = "low"
    tracking_indicators: int = 0
    third_party_cookies: int = 0
    insecure_cookies: int = 0
    recommendations: List[str] = Field(default_factory=list)
    scanned_at: Optional[datetime] = None


class CookieRiskFinding(BaseModel):
    cookie_name: str
    domain: str
    risk_level: str
    reasons: List[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    report_id: str
    url: str
    scanned_at: datetime
    total_cookies: int
    first_party_cookies: int
    third_party_cookies: int
    tracking_indicators: int
    insecure_cookies: int
    risk_score: int
    severity: str
    recommendations: List[str]
    findings: List[CookieRiskFinding]
    page_signals: PagePrivacySignals


class ReportListItem(BaseModel):
    report_id: str
    url: str
    scanned_at: datetime
    risk_score: int
    severity: str
