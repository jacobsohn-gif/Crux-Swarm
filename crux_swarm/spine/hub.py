"""Stigmergic Spine Hub (`StigmergicSpineHub`) & 4-Gear Elastic Swarm Coordinator.

Coordinates the Symmetric `Crux-Cell` fleet and powers the Away-From-Desk Mobile PWA:
1. Parameterized SQLite-WAL Stigmergic Blackboard (`spine_events` table + `read_since`).
2. SHA-256 Hash-Chained `ConsensusLedger` enforcing `INV-SWARM-1`:
   - Zero self-certification (`judge_cell_id not in contributor_cell_ids`).
   - Cryptographic `prev_hash -> entry_hash` verification.
3. Stigmergic Task Queue & Atomic File-Lease Broker (`swarm_tasks` & `file_leases` tables):
   - Cells autonomously claim tasks, acquire exclusive file leases (preventing race conditions),
     and submit candidate diffs through the 3-Stage `CascadingJudge` + `Crux-Evals` gate.
4. 4-Gear Automatic Gearbox (`G1_SOLO -> G2_STRIKE_PAIR -> G3_SPIKE_WORKTREES -> G4_CRUCIBLE`)
   with mid-flight stall upshifting into isolated `GitWorktreePool` shards & `git merge-tree`.
5. Away-From-Desk Mobile Decision Queue (`mobile_questions` table) + Push/Webhook alerts.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import contextlib
from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.request
import uuid
from typing import Any, Callable, Iterator

from crux_swarm.cell.judge import CandidatePatch, CascadingJudge
from crux_swarm.cell.node import CruxCellNode
from crux_swarm.cell.security import scrub_child_environment
from crux_swarm.cell.shadow_git import GitWorktreePool, ManagedWorktree


class SwarmConsensusViolation(PermissionError):
    """Raised when a ConsensusLedger commit violates INV-SWARM-1 (self-grading or broken hash chain)."""


class FileLeaseConflictError(RuntimeError):
    """Raised when a cell attempts to acquire a file lease already held by another active cell."""


class SwarmGear(str, Enum):
    AUTO = "auto"
    G1_SOLO = "g1_solo"
    G2_STRIKE_PAIR = "g2_strike_pair"
    G3_SPIKE_WORKTREES = "g3_spike_worktrees"
    G4_CRUCIBLE = "g4_crucible"


def select_initial_gear(prompt: str, requested: SwarmGear = SwarmGear.AUTO) -> SwarmGear:
    """Selects the starting swarm gear (`G1..G4`) from prompt complexity and structural keywords."""
    if requested != SwarmGear.AUTO:
        return requested
    words = prompt.split()
    low = prompt.lower()
    crucible_terms = ("architecture", "redesign", "algorithm", "optimize", "benchmark", "security audit", "race")
    shard_terms = ("refactor across", "multiple modules", "migrate all", "parallel", "worktree", "end-to-end")
    if (any(t in low for t in crucible_terms) and len(words) >= 10) or sum(1 for t in crucible_terms if t in low) >= 2:
        return SwarmGear.G4_CRUCIBLE
    if any(t in low for t in shard_terms) or len(words) >= 55:
        return SwarmGear.G3_SPIKE_WORKTREES
    if len(words) >= 14 or any(k in low for k in ("fix", "bug", "implement", "add", "patch")):
        return SwarmGear.G2_STRIKE_PAIR
    return SwarmGear.G1_SOLO


@dataclass(frozen=True)
class SpineEvent:
    seq: int
    event_id: str
    event_type: str
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
    kind: str
    question: str
    options: list[str]
    context_summary: str
    status: str
    answer: str | None
    created_at: float
    answered_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SwarmTaskCard:
    task_id: str
    title: str
    objective: str
    gear: str
    status: str  # PENDING | CLAIMED | COMPLETED | FAILED
    assigned_cell_id: str | None
    candidate_id: str | None
    created_at: float
    updated_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileLease:
    file_path: str
    cell_id: str
    acquired_at: float
    expires_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


ShardWorkerFn = Callable[[ManagedWorktree, "StigmergicSpineHub", str], None]


@dataclass
class SwarmUpshiftSummary:
    initial_gear: SwarmGear
    final_gear: SwarmGear
    upshifted: bool
    merged_workers: list[str]
    contract_deltas: list[SpineEvent]
    winning_candidate_id: str | None = None
    ledger_block: LedgerBlock | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StigmergicSpineHub:
    """Central Stigmergic Spine, Task/Lease Broker, 4-Gear Coordinator & Mobile Multiplexer."""

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
        self.jsonl_path = self.state_dir / "spine_events.jsonl"
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS swarm_tasks (
                    task_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    gear TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_cell_id TEXT,
                    candidate_id TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_leases (
                    file_path TEXT PRIMARY KEY,
                    cell_id TEXT NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL
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
            evt = SpineEvent(
                seq=seq,
                event_id=ev_id,
                event_type=event_type,
                cell_id=cell_id,
                scope=scope,
                summary=summary,
                created_at=now,
            )
            with self.jsonl_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(evt.to_dict(), sort_keys=True) + "\n")
        return evt

    def read_since(
        self,
        last_seq: int = 0,
        *,
        event_types: tuple[str, ...] | None = None,
        exclude_cell_id: str | None = None,
    ) -> list[SpineEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, event_id, event_type, cell_id, scope, summary, created_at FROM spine_events WHERE seq > ? ORDER BY seq ASC",
                (last_seq,),
            ).fetchall()
        out: list[SpineEvent] = []
        for r in rows:
            ev = SpineEvent(int(r[0]), str(r[1]), str(r[2]), str(r[3]), str(r[4]), str(r[5]), float(r[6]))
            if event_types and ev.event_type not in event_types:
                continue
            if exclude_cell_id and ev.cell_id == exclude_cell_id:
                continue
            out.append(ev)
        return out

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

    # ---- Stigmergic Task Queue & Atomic File-Lease Broker ----

    def enqueue_task(
        self,
        title: str,
        objective: str,
        *,
        gear: SwarmGear = SwarmGear.AUTO,
    ) -> SwarmTaskCard:
        resolved_gear = select_initial_gear(objective, requested=gear)
        now = time.time()
        tid = f"task_{uuid.uuid4().hex[:8]}"
        card = SwarmTaskCard(
            task_id=tid,
            title=title,
            objective=objective,
            gear=resolved_gear.value,
            status="PENDING",
            assigned_cell_id=None,
            candidate_id=None,
            created_at=now,
            updated_at=now,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO swarm_tasks
                (task_id, title, objective, gear, status, assigned_cell_id, candidate_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'PENDING', NULL, NULL, ?, ?)
                """,
                (tid, title, objective, resolved_gear.value, now, now),
            )
        self.post_event("TASK_ENQUEUED", "spine", f"Task `{tid}` ({title}) queued at gear `{resolved_gear.value}`.")
        return card

    def claim_next_task(self, cell_id: str) -> SwarmTaskCard | None:
        now = time.time()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT task_id, title, objective, gear, created_at FROM swarm_tasks WHERE status = 'PENDING' ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            tid, title, obj, gear_str, created_at = row
            conn.execute(
                "UPDATE swarm_tasks SET status = 'CLAIMED', assigned_cell_id = ?, updated_at = ? WHERE task_id = ?",
                (cell_id, now, tid),
            )
        self.post_event("TASK_CLAIMED", cell_id, f"Cell `{cell_id}` claimed task `{tid}` ({title}).")
        return SwarmTaskCard(
            task_id=tid,
            title=title,
            objective=obj,
            gear=gear_str,
            status="CLAIMED",
            assigned_cell_id=cell_id,
            candidate_id=None,
            created_at=float(created_at),
            updated_at=now,
        )

    def complete_task(
        self,
        task_id: str,
        *,
        cell_id: str,
        unified_diff: str,
        judge_cell_id: str = "cell-judge",
        judge_family: str = "anthropic",
    ) -> tuple[SwarmTaskCard, LedgerBlock]:
        """Verifies the cell's diff via `CascadingJudge` + `Crux-Evals` and commits to `ConsensusLedger`."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT title, objective, gear, created_at FROM swarm_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if not row:
                raise KeyError(f"Unknown task_id: {task_id}")
            title, objective, gear_str, created_at = row

        cand = CandidatePatch(
            candidate_id=f"cand_{uuid.uuid4().hex[:8]}",
            contributor_cell_ids=(cell_id,),
            family="gemini",
            unified_diff=unified_diff,
            summary=title,
        )
        judge = CascadingJudge(judge_cell_id=judge_cell_id, judge_family=judge_family)
        verdict = judge.run_stage_b_bars(objective, cand)
        eval_gate = judge.run_crux_evals_gate(objective, cand)
        approved = bool(verdict.passed and eval_gate["passed"])

        blk = self.record_consensus_block(
            candidate_id=cand.candidate_id,
            contributor_cell_ids=[cell_id],
            judge_cell_id=verdict.judge_cell_id,
            judge_family=verdict.judge_family,
            bars_score=verdict.score,
            approved=approved,
        )
        new_status = "COMPLETED" if approved else "FAILED"
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE swarm_tasks SET status = ?, candidate_id = ?, updated_at = ? WHERE task_id = ?",
                (new_status, cand.candidate_id, now, task_id),
            )
        self.post_event(
            "TASK_COMPLETED" if approved else "TASK_REJECTED",
            cell_id,
            f"Task `{task_id}` -> {new_status} (candidate={cand.candidate_id}, score={verdict.score:.2f})",
        )
        return (
            SwarmTaskCard(
                task_id=task_id,
                title=title,
                objective=objective,
                gear=gear_str,
                status=new_status,
                assigned_cell_id=cell_id,
                candidate_id=cand.candidate_id,
                created_at=float(created_at),
                updated_at=now,
            ),
            blk,
        )

    def list_tasks(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT task_id, title, objective, gear, status, assigned_cell_id, candidate_id, created_at, updated_at FROM swarm_tasks ORDER BY created_at DESC"
            ).fetchall()
        return [
            SwarmTaskCard(
                task_id=r[0],
                title=r[1],
                objective=r[2],
                gear=r[3],
                status=r[4],
                assigned_cell_id=r[5],
                candidate_id=r[6],
                created_at=r[7],
                updated_at=r[8],
            ).to_dict()
            for r in rows
        ]

    def acquire_file_lease(self, cell_id: str, file_path: str, *, ttl_seconds: float = 300.0) -> FileLease:
        """Acquires an atomic exclusive file lease so two cells never edit the same file concurrently."""
        norm_path = str(pathlib.PurePosixPath(file_path))
        now = time.time()
        expires = now + ttl_seconds
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT cell_id, acquired_at, expires_at FROM file_leases WHERE file_path = ?",
                (norm_path,),
            ).fetchone()
            if row and float(row[2]) > now and str(row[0]) != cell_id:
                raise FileLeaseConflictError(
                    f"File `{norm_path}` is already leased by cell `{row[0]}` until {row[2]:.0f}."
                )
            conn.execute(
                """
                INSERT OR REPLACE INTO file_leases (file_path, cell_id, acquired_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (norm_path, cell_id, now, expires),
            )
        self.post_event("LEASE_ACQUIRED", cell_id, f"Leased `{norm_path}` for {ttl_seconds:.0f}s", scope=norm_path)
        return FileLease(file_path=norm_path, cell_id=cell_id, acquired_at=now, expires_at=expires)

    def release_file_lease(self, cell_id: str, file_path: str) -> bool:
        norm_path = str(pathlib.PurePosixPath(file_path))
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM file_leases WHERE file_path = ? AND cell_id = ?",
                (norm_path, cell_id),
            )
            deleted = (cur.rowcount or 0) > 0
        if deleted:
            self.post_event("LEASE_RELEASED", cell_id, f"Released lease on `{norm_path}`", scope=norm_path)
        return deleted

    def list_file_leases(self) -> list[dict[str, Any]]:
        now = time.time()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT file_path, cell_id, acquired_at, expires_at FROM file_leases WHERE expires_at > ? ORDER BY acquired_at DESC",
                (now,),
            ).fetchall()
        return [
            FileLease(file_path=r[0], cell_id=r[1], acquired_at=r[2], expires_at=r[3]).to_dict()
            for r in rows
        ]

    # ---- 4-Gear Automatic Gearbox & Isolated Git Worktree Execution (CT-19) ----

    def execute_with_stall_upshift(
        self,
        repo_root: pathlib.Path,
        objective: str,
        *,
        solo_attempt: Callable[[], bool],
        parallel_shards: list[tuple[str, ShardWorkerFn]],
        judge_cell_id: str = "cell-judge",
        judge_family: str = "anthropic",
    ) -> SwarmUpshiftSummary:
        """Runs Gear 2 first; if `solo_attempt()` stalls, auto-upshifts into Gear 3 isolated worktrees."""
        g_start = SwarmGear.G2_STRIKE_PAIR
        notes: list[str] = []
        if solo_attempt():
            return SwarmUpshiftSummary(
                initial_gear=g_start,
                final_gear=g_start,
                upshifted=False,
                merged_workers=[],
                contract_deltas=[],
                notes=["Solved cleanly in Gear 2 without upshift."],
            )

        self.post_event("UPSHIFT", "gearbox", f"Upshifting Gear 2 -> Gear 3 worktrees on stall: {objective[:100]}")
        worktrees = GitWorktreePool(repo_root)
        managed: list[ManagedWorktree] = [worktrees.create(wid) for wid, _ in parallel_shards]
        try:
            with ThreadPoolExecutor(max_workers=max(1, len(managed))) as pool:
                futs = [
                    pool.submit(fn, wt, self, wid)
                    for (wid, fn), wt in zip(parallel_shards, managed)
                ]
                for fut in futs:
                    fut.result()

            for wt in managed:
                worktrees.commit_worktree(wt, message=f"shard {wt.worker_id}")

            if len(managed) >= 2:
                clean, detail = worktrees.can_merge_cleanly(managed[0].branch_name, managed[1].branch_name)
                if not clean:
                    notes.append(f"merge-tree detected conflict requiring integrator: {detail[:180]}")

            merged_ids: list[str] = []
            combined_diffs: list[str] = []
            for wt in managed:
                combined_diffs.append(worktrees.worktree_diff(wt))
                ok, msg = worktrees.merge_into_current(wt)
                if ok:
                    merged_ids.append(wt.worker_id)
                else:
                    notes.append(f"Conflict merging `{wt.worker_id}`: {msg[:180]}")

            cand = CandidatePatch(
                candidate_id=f"cand_{uuid.uuid4().hex[:8]}",
                contributor_cell_ids=tuple(merged_ids or [w.worker_id for w in managed]),
                family="gemini",
                unified_diff="\n".join(combined_diffs),
            )
            stage_a = CascadingJudge.run_stage_a(cand)
            blk = self.record_consensus_block(
                candidate_id=cand.candidate_id,
                contributor_cell_ids=list(cand.contributor_cell_ids),
                judge_cell_id=judge_cell_id,
                judge_family=judge_family,
                bars_score=1.0 if stage_a.passed else 0.0,
                approved=stage_a.passed,
            )
            deltas = self.read_since(0, event_types=("CONTRACT_DELTA",))
            return SwarmUpshiftSummary(
                initial_gear=g_start,
                final_gear=SwarmGear.G3_SPIKE_WORKTREES,
                upshifted=True,
                merged_workers=merged_ids,
                contract_deltas=deltas,
                winning_candidate_id=cand.candidate_id if stage_a.passed else None,
                ledger_block=blk,
                notes=notes + stage_a.reasons,
            )
        finally:
            for wt in managed:
                worktrees.cleanup(wt)

    # ---- SHA-256 Hash-Chained ConsensusLedger (`INV-SWARM-1`) ----

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

    # ---- Away-From-Desk Mobile Decision Inbox & Push Hooks ----

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

    @staticmethod
    def dispatch_to_peer_cli(prompt: str, *, agent_bin: str | None = None, timeout: float = 60.0) -> dict[str, Any]:
        """Zero-shell-interpolation adapter delegating a task to a peer CLI (`agentapi` / `USH_PEER_AGENT_BIN`)."""
        bin_spec = (agent_bin or os.environ.get("USH_PEER_AGENT_BIN") or "agentapi").strip()
        exe = shutil.which(bin_spec)
        if not exe:
            return {"returncode": 127, "output": f"Peer agent CLI `{bin_spec}` not found on PATH."}
        env = scrub_child_environment()
        env.pop("ANTIGRAVITY_SOURCE_METADATA", None)
        res = subprocess.run(
            [exe, "new-conversation", prompt],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {"returncode": res.returncode, "output": (res.stdout + "\n" + res.stderr).strip()}
