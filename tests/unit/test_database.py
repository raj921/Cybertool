"""Tests for database models and CRUD operations."""
import os
import tempfile
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.database import Base
from backend.db.models import Scan, Finding, ScanEvent


@pytest.fixture
def db_session():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    os.unlink(path)


def test_create_scan(db_session):
    scan = Scan(target="example.com", profile="normal", model_role="reasoning")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    assert scan.id is not None
    assert len(scan.id) == 12
    assert scan.target == "example.com"
    assert scan.status == "pending"
    assert scan.profile == "normal"


def test_create_finding(db_session):
    scan = Scan(target="example.com")
    db_session.add(scan)
    db_session.commit()

    finding = Finding(
        scan_id=scan.id,
        vuln_type="xss",
        severity="high",
        confidence=92.5,
        title="Reflected XSS on /search",
        url="https://example.com/search?q=test",
        poc='curl "https://example.com/search?q=<script>alert(1)</script>"',
    )
    db_session.add(finding)
    db_session.commit()

    assert finding.id is not None
    assert finding.severity == "high"
    assert finding.confidence == 92.5
    assert scan.findings[0].id == finding.id


def test_create_scan_event(db_session):
    scan = Scan(target="example.com")
    db_session.add(scan)
    db_session.commit()

    event = ScanEvent(
        scan_id=scan.id,
        event_type="thinking",
        data={"text": "Starting recon..."},
    )
    db_session.add(event)
    db_session.commit()

    assert event.id is not None
    assert event.event_type == "thinking"
    assert scan.events[0].data["text"] == "Starting recon..."


def test_scan_finding_relationship(db_session):
    scan = Scan(target="test.com")
    db_session.add(scan)
    db_session.commit()

    for i in range(3):
        db_session.add(Finding(
            scan_id=scan.id,
            vuln_type="sqli",
            severity="critical",
            title=f"SQLi #{i}",
        ))
    db_session.commit()

    assert len(scan.findings) == 3


def test_scan_scope_config_json(db_session):
    config = {"include_subdomains": True, "ports": "top100", "rate_limit": 10}
    scan = Scan(target="test.com", scope_config=config)
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    assert scan.scope_config["include_subdomains"] is True
    assert scan.scope_config["ports"] == "top100"
