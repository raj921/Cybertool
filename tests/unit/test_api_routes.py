"""Tests for FastAPI REST endpoints."""
import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.database import Base, get_db
from backend.main import app


@pytest.fixture
def client():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    os.unlink(path)


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_create_scan(client):
    resp = client.post("/api/scans", json={"target": "example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "example.com"
    assert data["status"] == "pending"
    assert len(data["id"]) == 12


def test_list_scans(client):
    client.post("/api/scans", json={"target": "a.com"})
    client.post("/api/scans", json={"target": "b.com"})
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_get_scan(client):
    create_resp = client.post("/api/scans", json={"target": "test.com"})
    scan_id = create_resp.json()["id"]

    resp = client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    assert resp.json()["target"] == "test.com"


def test_get_scan_not_found(client):
    resp = client.get("/api/scans/nonexistent")
    assert resp.status_code == 404


def test_get_findings_empty(client):
    create_resp = client.post("/api/scans", json={"target": "test.com"})
    scan_id = create_resp.json()["id"]
    resp = client.get(f"/api/scans/{scan_id}/findings")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_models(client):
    resp = client.get("/api/models")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["models"]) >= 4
    assert "defaults" in data


def test_create_scan_with_scope(client):
    resp = client.post("/api/scans", json={
        "target": "test.com",
        "scope_config": {"include_subdomains": True, "ports": "top100"},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["scope_config"]["include_subdomains"] is True
