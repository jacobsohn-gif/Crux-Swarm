"""Stigmergic Spine HTTP & Mobile PWA Gateway (`CruxSpineHTTPServer`).

Serves:
1. The Installable Mobile PWA Cockpit (`GET /`, `/manifest.json`, `/sw.js`).
2. Authenticated REST / JSON-RPC Endpoints (`/api/...`) protected by constant-time
   HMAC Bearer / Pairing Token verification:
   - `GET  /api/overview`: Fleet status, pending mobile questions, active tasks, file leases, events, ledger.
   - `GET  /api/cells/<id>/threads`: Full conversation thread DAG & thought traces for a cell.
   - `GET  /api/cells/<id>/viewport?wake=1`: Live socket-activated OS/Browser viewport frame.
   - `POST /api/cells/<id>/input`: Interactive touch-to-click, typing, key, and URL navigation into the cell browser.
   - `POST /api/questions/<id>/answer`: 1-tap mobile answer to `ask_user` or `policy_approval`.
   - `POST /api/cells/<id>/steer`: Live mid-turn `/steer` from your phone.
   - `POST /api/cells/<id>/btw`: Zero-history `/btw` side question from your phone.
   - `POST /api/tasks`: Enqueue a new 4-Gear task onto the Stigmergic Spine.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import pathlib
from typing import Any
from urllib.parse import parse_qs, urlparse

from crux_swarm.spine.hub import StigmergicSpineHub, SwarmGear

MOBILE_ASSETS_DIR = pathlib.Path(__file__).resolve().parent.parent / "mobile"


class CruxSpineGatewayHandler(BaseHTTPRequestHandler):
    hub: StigmergicSpineHub

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _check_auth(self, parsed_url: Any) -> bool:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr[7:].strip()
            if self.hub.verify_pairing_token(token):
                return True
        qs = parse_qs(parsed_url.query)
        q_tok = (qs.get("token") or [""])[0]
        return self.hub.verify_pairing_token(q_tok)

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_static(self, filename: str, content_type: str) -> None:
        fp = MOBILE_ASSETS_DIR / filename
        if not fp.is_file():
            self._send_json(404, {"error": "Asset not found"})
            return
        raw = fp.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._send_static("index.html", "text/html; charset=utf-8")
            return
        if path == "/manifest.json":
            self._send_static("manifest.json", "application/manifest+json; charset=utf-8")
            return
        if path == "/sw.js":
            self._send_static("sw.js", "application/javascript; charset=utf-8")
            return
        if path == "/api/health":
            self._send_json(200, {"status": "ok", "service": "crux-stigmergic-spine"})
            return

        if not self._check_auth(parsed):
            self._send_json(401, {"error": "Unauthorized: valid mobile pairing token required"})
            return

        if path == "/api/overview":
            valid_chain, block_count = self.hub.verify_ledger_chain()
            self._send_json(
                200,
                {
                    "cells": self.hub.list_cells(),
                    "pending_questions": self.hub.list_mobile_questions(status="PENDING"),
                    "recent_questions": self.hub.list_mobile_questions(),
                    "tasks": self.hub.list_tasks(),
                    "file_leases": self.hub.list_file_leases(),
                    "events": self.hub.list_events(limit=30),
                    "ledger": {
                        "chain_valid": valid_chain,
                        "block_count": block_count,
                        "blocks": self.hub.list_ledger_blocks(),
                    },
                },
            )
            return

        if path == "/api/tasks":
            self._send_json(200, {"tasks": self.hub.list_tasks()})
            return

        if path == "/api/leases":
            self._send_json(200, {"file_leases": self.hub.list_file_leases()})
            return

        if path.startswith("/api/cells/") and path.endswith("/threads"):
            parts = path.strip("/").split("/")
            cell_id = parts[2]
            cell = self.hub.get_cell(cell_id)
            if cell is None:
                self._send_json(404, {"error": f"Unknown cell: {cell_id}"})
                return
            self._send_json(
                200,
                {
                    "cell_id": cell_id,
                    "active_thread_id": cell.dag.active_thread_id,
                    "turns": cell.dag.list_turns(),
                },
            )
            return

        if path.startswith("/api/cells/") and path.endswith("/viewport"):
            parts = path.strip("/").split("/")
            cell_id = parts[2]
            cell = self.hub.get_cell(cell_id)
            if cell is None:
                self._send_json(404, {"error": f"Unknown cell: {cell_id}"})
                return
            qs = parse_qs(parsed.query)
            wake = (qs.get("wake") or ["0"])[0] in ("1", "true", "yes")
            snap = cell.display.capture_viewport(wake_if_needed=wake)
            self._send_json(200, snap.to_dict())
            return

        self._send_json(404, {"error": f"Route not found: {path}"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._check_auth(parsed):
            self._send_json(401, {"error": "Unauthorized: valid mobile pairing token required"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            body = json.loads(raw_body) if raw_body.strip() else {}
        except json.JSONDecodeError:
            body = {}

        if path == "/api/tasks":
            title = str(body.get("title", "Swarm Task")).strip()
            objective = str(body.get("objective", title)).strip()
            gear_raw = str(body.get("gear", "auto")).lower().strip()
            gear = SwarmGear(gear_raw) if gear_raw in {g.value for g in SwarmGear} else SwarmGear.AUTO
            card = self.hub.enqueue_task(title, objective, gear=gear)
            self._send_json(201, {"status": "ENQUEUED", "task": card.to_dict()})
            return

        if path.startswith("/api/questions/") and path.endswith("/answer"):
            qid = path.strip("/").split("/")[2]
            ans = str(body.get("answer", "")).strip()
            if not ans:
                self._send_json(400, {"error": "answer is required"})
                return
            try:
                card = self.hub.answer_mobile_question(qid, ans)
                self._send_json(200, {"status": "ANSWERED", "question": card.to_dict()})
            except KeyError as exc:
                self._send_json(404, {"error": str(exc)})
            return

        if path.startswith("/api/cells/") and path.endswith("/input"):
            cell_id = path.strip("/").split("/")[2]
            cell = self.hub.get_cell(cell_id)
            if cell is None:
                self._send_json(404, {"error": f"Unknown cell: {cell_id}"})
                return
            action = str(body.get("action", "click")).strip()
            snap = cell.display.dispatch_input(
                action,  # type: ignore[arg-type]
                x=int(body["x"]) if "x" in body and body["x"] is not None else None,
                y=int(body["y"]) if "y" in body and body["y"] is not None else None,
                text=str(body["text"]) if "text" in body and body["text"] is not None else None,
                key=str(body["key"]) if "key" in body and body["key"] is not None else None,
                url=str(body["url"]) if "url" in body and body["url"] is not None else None,
            )
            self.hub.sync_cell_state(cell)
            self._send_json(200, snap.to_dict())
            return

        if path.startswith("/api/cells/") and path.endswith("/steer"):
            cell_id = path.strip("/").split("/")[2]
            text = str(body.get("text", "")).strip()
            try:
                snap = self.hub.steer_cell_from_mobile(cell_id, text)
                self._send_json(200, {"status": "STEERED", "cell": snap})
            except KeyError as exc:
                self._send_json(404, {"error": str(exc)})
            return

        if path.startswith("/api/cells/") and path.endswith("/btw"):
            cell_id = path.strip("/").split("/")[2]
            question = str(body.get("question", "")).strip()
            try:
                reply = self.hub.ask_btw_from_mobile(cell_id, question)
                self._send_json(200, {"status": "OK", "cell_id": cell_id, "reply": reply})
            except KeyError as exc:
                self._send_json(404, {"error": str(exc)})
            return

        self._send_json(404, {"error": f"POST route not found: {path}"})


def create_spine_http_server(
    hub: StigmergicSpineHub,
    host: str = "127.0.0.1",
    port: int = 8890,
) -> ThreadingHTTPServer:
    """Creates a threaded HTTP server bound to `hub`."""

    class _BoundHandler(CruxSpineGatewayHandler):
        pass

    _BoundHandler.hub = hub
    return ThreadingHTTPServer((host, port), _BoundHandler)
