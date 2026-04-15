from __future__ import annotations

import json
import asyncio

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from backend.db.database import SessionLocal
from backend.db.models import Scan, ScanEvent
from backend.agent.engine import AgentEngine


class ScanManager:
    """Manages active scan sessions and their WebSocket connections."""

    def __init__(self):
        self._active: dict[str, AgentEngine] = {}
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        if scan_id in self._connections:
            self._connections[scan_id] = [
                c for c in self._connections[scan_id] if c is not ws
            ]

    async def broadcast(self, scan_id: str, event: dict) -> None:
        dead: list[WebSocket] = []
        for ws in self._connections.get(scan_id, []):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)

        self._persist_event(scan_id, event)

    def _persist_event(self, scan_id: str, event: dict) -> None:
        try:
            db = SessionLocal()
            db.add(ScanEvent(
                scan_id=scan_id,
                event_type=event.get("type", "unknown"),
                data=event,
            ))
            db.commit()
            db.close()
        except Exception:
            pass

    async def start_scan(self, scan_id: str, target: str, scope_config: dict | None = None, model_role: str = "reasoning") -> None:
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "running"
            db.commit()
        db.close()

        engine = AgentEngine(
            scan_id=scan_id,
            target=target,
            scope_config=scope_config,
            model_role=model_role,
        )
        engine.on_event(lambda event: self.broadcast(scan_id, event))
        self._active[scan_id] = engine

        try:
            summary = await engine.run()
        except Exception as exc:
            await self.broadcast(scan_id, {"type": "error", "text": str(exc), "scan_id": scan_id})
            summary = {}
        finally:
            self._active.pop(scan_id, None)
            db = SessionLocal()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "completed"
                from datetime import datetime, timezone
                scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            db.close()

    def stop_scan(self, scan_id: str) -> None:
        engine = self._active.get(scan_id)
        if engine:
            engine.stop()


scan_manager = ScanManager()


async def websocket_endpoint(ws: WebSocket, scan_id: str) -> None:
    await scan_manager.connect(scan_id, ws)
    try:
        while True:
            data = await ws.receive_json()
            action = data.get("action")

            if action == "start":
                target = data.get("target", "")
                scope_config = data.get("scope_config")
                model_role = data.get("model_role", "reasoning")
                asyncio.create_task(
                    scan_manager.start_scan(scan_id, target, scope_config, model_role)
                )

            elif action == "stop":
                scan_manager.stop_scan(scan_id)

    except WebSocketDisconnect:
        scan_manager.disconnect(scan_id, ws)
    except Exception:
        scan_manager.disconnect(scan_id, ws)
