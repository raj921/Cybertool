from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.db.database import get_db
from backend.db.models import Scan, Finding
from backend.agent.models import list_models
from backend.config import settings

router = APIRouter(prefix="/api")


class ScanCreate(BaseModel):
    target: str
    profile: str = "normal"
    scope_config: dict | None = None
    model_role: str = "reasoning"


class ScanResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    target: str
    status: str
    profile: str
    model_role: str
    created_at: str
    findings_count: int
    scope_config: dict | None = None


class FindingResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    vuln_type: str
    severity: str
    confidence: float
    title: str
    description: str
    url: str
    poc: str
    cvss_score: float | None
    verified: int
    created_at: str


# --- Scan endpoints ---

@router.post("/scans", response_model=ScanResponse)
def create_scan(body: ScanCreate, db: Session = Depends(get_db)):
    scan = Scan(
        target=body.target,
        profile=body.profile,
        scope_config=body.scope_config,
        model_role=body.model_role,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return ScanResponse(
        id=scan.id,
        target=scan.target,
        status=scan.status,
        profile=scan.profile,
        model_role=scan.model_role,
        created_at=scan.created_at.isoformat(),
        findings_count=0,
        scope_config=scan.scope_config,
    )


@router.get("/scans", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(50).all()
    return [
        ScanResponse(
            id=s.id,
            target=s.target,
            status=s.status,
            profile=s.profile,
            model_role=s.model_role,
            created_at=s.created_at.isoformat(),
            findings_count=len(s.findings),
            scope_config=s.scope_config,
        )
        for s in scans
    ]


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(
        id=scan.id,
        target=scan.target,
        status=scan.status,
        profile=scan.profile,
        model_role=scan.model_role,
        created_at=scan.created_at.isoformat(),
        findings_count=len(scan.findings),
        scope_config=scan.scope_config,
    )


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
def get_findings(scan_id: str, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.created_at.desc()).all()
    return [
        FindingResponse(
            id=f.id,
            vuln_type=f.vuln_type,
            severity=f.severity,
            confidence=f.confidence,
            title=f.title,
            description=f.description,
            url=f.url,
            poc=f.poc,
            cvss_score=f.cvss_score,
            verified=f.verified,
            created_at=f.created_at.isoformat(),
        )
        for f in findings
    ]


# --- Model endpoints ---

@router.get("/models")
def get_models():
    return {"models": list_models(), "defaults": settings.models}


# --- Reports ---

@router.get("/scans/{scan_id}/report")
def get_report(scan_id: str, format: str = "markdown", db: Session = Depends(get_db)):
    from backend.reporting.generator import generate_markdown_report, generate_json_report, generate_html_report
    from fastapi.responses import PlainTextResponse, HTMLResponse

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_data = [
        {
            "type": f.vuln_type,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "url": f.url,
            "poc": f.poc,
            "confidence": f.confidence,
            "payload": f.metadata_json.get("payload", "") if f.metadata_json else "",
        }
        for f in scan.findings
    ]

    if format == "json":
        return PlainTextResponse(generate_json_report(scan.target, findings_data), media_type="application/json")
    elif format == "html":
        return HTMLResponse(generate_html_report(scan.target, findings_data))
    else:
        return PlainTextResponse(generate_markdown_report(scan.target, findings_data), media_type="text/markdown")


# --- Health ---

@router.get("/health")
def health():
    return {"status": "ok", "service": "cyberhunter-backend"}
