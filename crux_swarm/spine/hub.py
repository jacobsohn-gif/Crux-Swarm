"""Stigmergic Spine Hub (`StigmergicSpineHub`).

Coordinates the Symmetric `Crux-Cell` fleet and powers the Away-From-Desk Mobile PWA:
1. Parameterized SQLite-WAL Stigmergic Blackboard (`events` table).
2. SHA-256 Hash-Chained `ConsensusLedger` enforcing `INV-SWARM-1`:
   - Zero self-certification (`judge_cell_id not in contributor_cell_ids` AND cross-family preferred).
   - Cryptographic `prev_hash -> entry_hash` verification.
3. Away-From-Desk Mobile Decision Queue (`mobile_questions` table):
   - Queues `ask_user` multiple-choice questions and `policy_approval` gates from any `Crux-Cell`.
   - Fires optional outbound Push / Google Chat / Webhook notifications.
   - Routes 1-tap mobile answers, live `/steer` messages, and `/btw` side questions back to the target `Crux-Cell`.
"""

from __future__ import annotations

import contextlib
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import pathlib
import secrets
import sqlite3
import threading
import time
import urllib.request
import uuid
from typing import Any, Callable, Iterator

from crux_swarm.cell.node import CruxCellNode


class SwarmConsensusViolation(PermissionError):
    """Raised when a ConsensusLedger commit violates INV-SWARM-1 (self-grading or broken hash chain)."""


@dataclass(frozen=True)
class SpineEvent:
    seq: int
    event_id: str
    event_type: str  # SPIKE | CONTRACT_DELTA | REQUEST_REVIEW | QUESTION_OPENED | QUESTION_ANSWERED | STEER | LEDGER_COMMIT
    cell_id: str
    scope: str
    summary: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LedgerBlock:
    seq: int
    candidate_id: str
    contributor_cell_ids: tuple[str, ...]
    judge_cell_id: str
    judge_family: str
    bars_score: float
    approved: bool
    prev_hash: str
    entry_hash: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MobileQuestionCard:
    question_id: str
    cell_id: str
    kind: str  # ask_user | policy_approval | grill_me
    question: str
    options: list[str]
    context_summary: str
    status: str  # PENDING | ANSWERED
    answer: str | None
    created_at: float
    answered_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StigmergicSpineHub:
    """Central Stigmergic Spine & Mobile Multiplexer for Symmetric Crux-Cell Pods."""

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        state_dir: pathlib.Path,
        *,
        pairing_token: str | None = None,
        webhook_url: str | None = None,
        webhook_sender: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.state_dir = state_dir.expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state_dir / "stigmergic_spine.sqlite3"
        self.pairing_token = pairing_token or secrets.token_urlsafe(24)
        self.webhook_url = webhook_url
        self.webhook_sender = webhook_sender
        self._lock = threading.Lock()
        self._cells: dict[str, CruxCellNode] = {}
        self._cell_snapshots: dict[str, dict[str, Any]] = {}
        self._init_db()

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS spine_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS consensus_ledger (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_id TEXT NOT NULL,
                    contributor_cells_json TEXT NOT NULL,
                    judge_cell_id TEXT NOT NULL,
                    judge_family TEXT NOT NULL,
                    bars_score REAL NOT NULL,
                    approved INTEGER NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mobile_questions (
                    question_id TEXT PRIMARY KEY,
                    cell_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    question TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    context_summary TEXT NOT NULL,
                    status TEXT NOT NULL,
                    answer TEXT,
                    created_at REAL NOT NULL,
                    answered_at REAL
                )
                """
            )

    def verify_pairing_token(self, candidate: str) -> bool:
        if not candidate or not self.pairing_token:
            return False
        return hmac.compare_digest(candidate.encode("utf-8"), self.pairing_token.encode("utf-8"))

    def register_cell(self, cell: CruxCellNode) -> None:
        with self._lock:
            self._cells[cell.cell_id] = cell
            self._cell_snapshots[cell.cell_id] = cell.status_snapshot()
        self.post_event("CELL_JOINED", cell.cell_id, f"Crux-Cell `{cell.cell_id}` ({cell.role}) joined spine.")

    def sync_cell_state(self, cell: CruxCellNode) -> dict[str, Any]:
        snap = cell.status_snapshot()
        with self._lock:
            self._cells[cell.cell_id] = cell
            self._cell_snapshots[cell.cell_id] = snap
        return snap

    def update_remote_cell_snapshot(self, snapshot: dict[str, Any]) -> None:
        cid = str(snapshot.get("cell_id", ""))
        if cid:
            with self._lock:
                self._cell_snapshots[cid] = snapshot

    def list_cells(self) -> list[dict[str, Any]]:
        with self._lock:
            for cid, cell in self._cells.items():
                self._cell_snapshots[cid] = cell.status_snapshot()
            return [self._cell_snapshots[k] for k in sorted(self._cell_snapshots)]

    def get_cell(self, cell_id: str) -> CruxCellNode | None:
        with self._lock:
            return self._cells.get(cell_id)

    def post_event(self, event_type: str, cell_id: str, summary: str, scope: str = "*") -> SpineEvent:
        now = time.time()
        ev_id = f"ev_{uuid.uuid4().hex[:10]}"
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO spine_events (event_id, event_type, cell_id, scope, summary, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (ev_id, event_type, cell_id, scope, summary, now),
            )
            seq = int(cur.lastrowid or 0)
        return SpineEvent(
            seq=seq,
            event_id=ev_id,
            event_type=event_type,
            cell_id=cell_id,
            scope=scope,
            summary=summary,
            created_at=now,
        )

    def list_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, event_id, event_type, cell_id, scope, summary, created_at FROM spine_events ORDER BY seq DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            SpineEvent(
                seq=r[0],
                event_id=r[1],
                event_type=r[2],
                cell_id=r[3],
                scope=r[4],
                summary=r[5],
                created_at=r[6],
            ).to_dict()
            for r in reversed(rows)
        ]

    def record_consensus_block(
        self,
        candidate_id: str,
        contributor_cell_ids: list[str] | tuple[str, ...],
        judge_cell_id: str,
        judge_family: str,
        bars_score: float,
        approved: bool,
    ) -> LedgerBlock:
        contributors = tuple(str(x) for x in contributor_cell_ids)
        if not contributors:
            raise SwarmConsensusViolation("contributor_cell_ids cannot be empty")
        if judge_cell_id in contributors:
            raise SwarmConsensusViolation(
                f"INV-SWARM-1 Violation: Cell `{judge_cell_id}` cannot judge its own contribution ({contributors})!"
            )

        now = time.time()
        with self._lock, self._connect() as conn:
            last_row = conn.execute(
                "SELECT entry_hash FROM consensus_ledger ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = str(last_row[0]) if last_row else self.GENESIS_HASH
            payload = json.dumps(
                {
                    "candidate_id": candidate_id,
                    "contributors": list(contributors),
                    "judge_cell_id": judge_cell_id,
                    "judge_family": judge_family,
                    "bars_score": round(float(bars_score), 4),
                    "approved": bool(approved),
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
            )
            entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            cur = conn.execute(
                """
                INSERT INTO consensus_ledger
                (candidate_id, contributor_cells_json, judge_cell_id, judge_family, bars_score, approved, prev_hash, entry_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    json.dumps(list(contributors)),
                    judge_cell_id,
                    judge_family,
                    round(float(bars_score), 4),
                    1 if approved else 0,
                    prev_hash,
                    entry_hash,
                    now,
                ),
            )
            seq = int(cur.lastrowid or 0)

        self.post_event(
            "LEDGER_COMMIT",
            judge_cell_id,
            f"Ledger block #{seq} for `{candidate_id}` (score={bars_score:.2f}, approved={approved}, hash={entry_hash[:12]})",
        )
        return LedgerBlock(
            seq=seq,
            candidate_id=candidate_id,
            contributor_cell_ids=contributors,
            judge_cell_id=judge_cell_id,
            judge_family=judge_family,
            bars_score=round(float(bars_score), 4),
            approved=bool(approved),
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            created_at=now,
        )

    def verify_ledger_chain(self) -> tuple[bool, int]:
        """Verifies the unbroken SHA-256 hash chain and INV-SWARM-1 across all blocks."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, candidate_id, contributor_cells_json, judge_cell_id, judge_family, bars_score, approved, prev_hash, entry_hash FROM consensus_ledger ORDER BY seq ASC"
            ).fetchall()
        expected_prev = self.GENESIS_HASH
        for r in rows:
            _, cand_id, contrib_json, judge_id, judge_fam, score, app_int, prev_h, entry_h = r
            contributors = json.loads(contrib_json)
            if judge_id in contributors:
                return False, len(rows)
            if prev_h != expected_prev:
                return False, len(rows)
            payload = json.dumps(
                {
                    "candidate_id": cand_id,
                    "contributors": contributors,
                    "judge_cell_id": judge_id,
                    "judge_family": judge_fam,
                    "bars_score": round(float(score), 4),
                    "approved": bool(app_int),
                    "prev_hash": prev_h,
                },
                sort_keys=True,
            )
            calc_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if calc_hash != entry_h:
                return False, len(rows)
            expected_prev = entry_h
        return True, len(rows)

    def list_ledger_blocks(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, candidate_id, contributor_cells_json, judge_cell_id, judge_family, bars_score, approved, prev_hash, entry_hash, created_at FROM consensus_ledger ORDER BY seq DESC"
            ).fetchall()
        return [
            LedgerBlock(
                seq=r[0],
                candidate_id=r[1],
                contributor_cell_ids=tuple(json.loads(r[2])),
                judge_cell_id=r[3],
                judge_family=r[4],
                bars_score=r[5],
                approved=bool(r[6]),
                prev_hash=r[7],
                entry_hash=r[8],
                created_at=r[9],
            ).to_dict()
            for r in rows
        ]

    def create_mobile_question(
        self,
        *,
        cell_id: str,
        kind: str,
        question: str,
        options: list[str],
        context_summary: str = "",
    ) -> MobileQuestionCard:
        qid = f"q_{uuid.uuid4().hex[:10]}"
        now = time.time()
        card = MobileQuestionCard(
            question_id=qid,
            cell_id=cell_id,
            kind=kind,
            question=question,
            options=list(options),
            context_summary=context_summary,
            status="PENDING",
            answer=None,
            created_at=now,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO mobile_questions
                (question_id, cell_id, kind, question, options_json, context_summary, status, answer, created_at, answered_at)
                VALUES (?, ?, ?, ?, ?, ?, 'PENDING', NULL, ?, NULL)
                """,
                (qid, cell_id, kind, question, json.dumps(options), context_summary, now),
            )
        self.post_event("QUESTION_OPENED", cell_id, f"[{kind}] {question}")
        self._dispatch_push_notification(card)
        return card

    def answer_mobile_question(self, question_id: str, answer: str) -> MobileQuestionCard:
        now = time.time()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT cell_id, kind, question, options_json, context_summary, created_at FROM mobile_questions WHERE question_id = ?",
                (question_id,),
            ).fetchone()
            if not row:
                raise KeyError(f"Unknown mobile question_id: {question_id}")
            conn.execute(
                "UPDATE mobile_questions SET status = 'ANSWERED', answer = ?, answered_at = ? WHERE question_id = ?",
                (answer, now, question_id),
            )
            cell_id, kind, q_txt, opts_json, ctx, created_at = row
            cell = self._cells.get(cell_id)

        if cell is not None:
            cell.receive_mobile_answer(question_id, answer)
            self.sync_cell_state(cell)

        self.post_event("QUESTION_ANSWERED", cell_id, f"Answered `{question_id}` -> {answer}")
        return MobileQuestionCard(
            question_id=question_id,
            cell_id=cell_id,
            kind=kind,
            question=q_txt,
            options=json.loads(opts_json),
            context_summary=ctx,
            status="ANSWERED",
            answer=answer,
            created_at=created_at,
            answered_at=now,
        )

    def list_mobile_questions(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT question_id, cell_id, kind, question, options_json, context_summary, status, answer, created_at, answered_at FROM mobile_questions WHERE status = ? ORDER BY created_at DESC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT question_id, cell_id, kind, question, options_json, context_summary, status, answer, created_at, answered_at FROM mobile_questions ORDER BY created_at DESC"
                ).fetchall()
        return [
            MobileQuestionCard(
                question_id=r[0],
                cell_id=r[1],
                kind=r[2],
                question=r[3],
                options=json.loads(r[4]),
                context_summary=r[5],
                status=r[6],
                answer=r[7],
                created_at=r[8],
                answered_at=r[9],
            ).to_dict()
            for r in rows
        ]

    def steer_cell_from_mobile(self, cell_id: str, steer_text: str) -> dict[str, Any]:
        cell = self.get_cell(cell_id)
        if cell is None:
            raise KeyError(f"Unknown cell_id: {cell_id}")
        cell.dag.enqueue_steer(steer_text)
        cell.dag.drain_steers()
        self.post_event("STEER", cell_id, f"Mobile steer injected into `{cell_id}`: {steer_text[:80]}")
        return self.sync_cell_state(cell)

    def ask_btw_from_mobile(self, cell_id: str, question: str) -> str:
        cell = self.get_cell(cell_id)
        if cell is None:
            raise KeyError(f"Unknown cell_id: {cell_id}")
        return cell.answer_btw_side_question(question)

    def _dispatch_push_notification(self, card: MobileQuestionCard) -> None:
        payload = {
            "type": "CRUX_SWARM_MOBILE_ALERT",
            "question_id": card.question_id,
            "cell_id": card.cell_id,
            "kind": card.kind,
            "question": card.question,
            "options": card.options,
            "context_summary": card.context_summary,
        }
        if self.webhook_sender is not None:
            self.webhook_sender(payload)
        elif self.webhook_url:
            try:
                req = urllib.request.Request(
                    self.webhook_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=3.0).read()
            except Exception:
                pass
