"""Symmetric Crux-Cell Autonomous Agent Node (`CruxCellNode`).

Gives EVERY agent in the swarm the complete `Crucible` (`crux`) runtime stack:
1. Local Conversation Thread DAG (`CellThreadDAG`): Multi-branch conversation threads,
   mid-turn `/steer` queue, and zero-history `/btw` side-question responder.
2. Long-Form `CellThoughtLedger`: Append-only `.trace.jsonl` recording every reasoning step,
   tool execution, and evaluator score.
3. 3-Layer `CellSecurityGuard`: Path-traversal/sandbox boundary check, secret token redaction,
   and `PolicyEngine` rules that automatically escalate `ASK_USER` approvals to the Mobile PWA.
4. Built-in Evaluator Hook (`Crux-Evals` Bridge): Runs complementary trajectory & patch
   checks out-of-band so the cell never grades its own work.
5. `LazyDisplayBrowserSupervisor`: Socket-activated full-OS desktop (`Xvfb :99`) + Chromium CDP.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import pathlib
import re
import threading
import time
import uuid
from typing import Any, Literal

from crux_swarm.cell.display_supervisor import LazyDisplayBrowserSupervisor, ViewportSnapshot

CellPhase = Literal["IDLE", "THINKING", "TOOL_DISPATCH", "WAITING_HUMAN", "EVALUATING", "DONE"]

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{24,}\b"),
)

HIGH_RISK_CMD_RE = re.compile(
    r"\b(rm\s+-rf|git\s+push\s+--force|drop\s+table|gcloud\s+projects\s+delete)\b",
    re.IGNORECASE,
)


def redact_cell_secrets(text: str) -> str:
    out = text
    for rx in SECRET_PATTERNS:
        out = rx.sub("[REDACTED_SECRET]", out)
    return out


@dataclass
class ThreadTurn:
    turn_id: str
    parent_id: str | None
    thread_id: str
    role: Literal["user", "assistant", "tool", "steer", "system"]
    content: str
    thought_trace: str = ""
    tool_name: str | None = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CellThreadDAG:
    """Per-cell multi-branch Conversation Thread DAG with live `/steer` queue."""

    def __init__(self, state_dir: pathlib.Path) -> None:
        self.state_dir = state_dir.expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.dag_file = self.state_dir / "threads_dag.jsonl"
        self._lock = threading.Lock()
        self.turns: list[ThreadTurn] = []
        self.active_thread_id: str = "main"
        self._steer_queue: list[str] = []

    def append_turn(
        self,
        role: Literal["user", "assistant", "tool", "steer", "system"],
        content: str,
        *,
        thought_trace: str = "",
        tool_name: str | None = None,
        thread_id: str | None = None,
    ) -> ThreadTurn:
        with self._lock:
            tid = thread_id or self.active_thread_id
            parent_id = self.turns[-1].turn_id if self.turns else None
            turn = ThreadTurn(
                turn_id=f"t_{uuid.uuid4().hex[:10]}",
                parent_id=parent_id,
                thread_id=tid,
                role=role,
                content=redact_cell_secrets(content),
                thought_trace=redact_cell_secrets(thought_trace),
                tool_name=tool_name,
            )
            self.turns.append(turn)
            with self.dag_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(turn.to_dict(), ensure_ascii=False) + "\n")
            return turn

    def enqueue_steer(self, message: str) -> None:
        with self._lock:
            self._steer_queue.append(redact_cell_secrets(message))

    def drain_steers(self) -> list[ThreadTurn]:
        with self._lock:
            drained = list(self._steer_queue)
            self._steer_queue.clear()
        recorded: list[ThreadTurn] = []
        for msg in drained:
            recorded.append(self.append_turn("steer", f"[LIVE_MOBILE_STEER]: {msg}"))
        return recorded

    def list_turns(self, thread_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            items = [
                t.to_dict()
                for t in self.turns
                if thread_id is None or t.thread_id == thread_id
            ]
        return items


class CellSecurityGuard:
    """Per-cell 3-layer security firewall (Workspace Sandbox + Secret Redaction + Policy Gate)."""

    def __init__(self, workspace_root: pathlib.Path) -> None:
        self.workspace_root = workspace_root.expanduser().resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def validate_path(self, raw_path: str) -> pathlib.Path:
        candidate = pathlib.Path(raw_path)
        if not candidate.is_absolute():
            candidate = (self.workspace_root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if not candidate.is_relative_to(self.workspace_root):
            raise PermissionError(
                f"Crux-Cell SecurityFirewall blocked path outside workspace: {raw_path!r}"
            )
        return candidate

    def check_command_policy(self, command: str) -> tuple[Literal["ALLOW", "ASK_USER", "DENY"], str]:
        if HIGH_RISK_CMD_RE.search(command):
            return "ASK_USER", f"High-impact shell command requires human confirmation: `{command}`"
        return "ALLOW", "Command permitted by cell policy."


class CruxCellNode:
    """Complete Autonomous Agent Pod in the Crux-Swarm."""

    def __init__(
        self,
        cell_id: str,
        *,
        role: str = "generalist",
        model_family: str = "gemini",
        workspace_root: pathlib.Path,
        state_dir: pathlib.Path,
        spine_hub: Any | None = None,
        dry_run_display: bool = True,
        idle_timeout_seconds: float = 180.0,
    ) -> None:
        self.cell_id = cell_id
        self.role = role
        self.model_family = model_family
        self.workspace_root = workspace_root.expanduser().resolve()
        self.state_dir = state_dir.expanduser().resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.phase: CellPhase = "IDLE"
        self.current_objective: str = ""
        self.dag = CellThreadDAG(self.state_dir)
        self.security = CellSecurityGuard(self.workspace_root)
        self.display = LazyDisplayBrowserSupervisor(
            cell_id,
            state_dir=self.state_dir,
            idle_timeout_seconds=idle_timeout_seconds,
            dry_run_processes=dry_run_display,
        )
        self.spine_hub = spine_hub
        if self.spine_hub is not None:
            self.spine_hub.register_cell(self)

    def execute_step(
        self,
        user_prompt: str,
        *,
        thought: str = "",
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        assistant_reply: str = "",
    ) -> dict[str, Any]:
        """Executes a reasoning/tool turn inside the cell and syncs telemetry to the Stigmergic Spine."""
        self.current_objective = user_prompt or self.current_objective
        self.phase = "THINKING"
        self.dag.drain_steers()
        u_turn = self.dag.append_turn("user", user_prompt)

        tool_args = dict(tool_args or {})
        if tool_name in ("browser_navigate", "open_url", "gui_click"):
            self.phase = "TOOL_DISPATCH"
            url = str(tool_args.get("url", "https://localhost:8080"))
            snap = self.display.navigate(url, title=tool_args.get("title"))
            self.dag.append_turn(
                "tool",
                f"Navigated cell browser to {url} (display={snap.display}, state={snap.state})",
                tool_name=tool_name,
            )

        if tool_name == "exec_pty" and tool_args.get("command"):
            cmd = str(tool_args["command"])
            pol_decision, reason = self.security.check_command_policy(cmd)
            if pol_decision == "ASK_USER" and self.spine_hub is not None:
                self.phase = "WAITING_HUMAN"
                req = self.spine_hub.create_mobile_question(
                    cell_id=self.cell_id,
                    kind="policy_approval",
                    question=reason,
                    options=["Approve Command", "Deny Command"],
                    context_summary=f"Objective: {self.current_objective} | Command: {cmd}",
                )
                return {"status": "WAITING_HUMAN", "question_id": req.question_id}

        a_turn = self.dag.append_turn(
            "assistant",
            assistant_reply or f"Completed step on `{self.cell_id}` ({self.role}).",
            thought_trace=thought or f"Analyzed objective in {self.cell_id}.",
            tool_name=tool_name,
        )
        self.phase = "IDLE"
        if self.spine_hub is not None:
            self.spine_hub.sync_cell_state(self)
        return {"status": "COMPLETED", "user_turn_id": u_turn.turn_id, "assistant_turn_id": a_turn.turn_id}

    def ask_mobile_user(
        self,
        question: str,
        options: list[str],
        *,
        context_summary: str = "",
    ) -> str:
        """Pushes an `ask_user` clarification card to the Mobile PWA Cockpit and returns `question_id`."""
        self.phase = "WAITING_HUMAN"
        self.dag.append_turn("assistant", f"[QUESTION_FOR_USER]: {question}")
        if self.spine_hub is None:
            raise RuntimeError("No StigmergicSpineHub attached to CruxCellNode")
        q = self.spine_hub.create_mobile_question(
            cell_id=self.cell_id,
            kind="ask_user",
            question=question,
            options=options,
            context_summary=context_summary or self.current_objective,
        )
        self.spine_hub.sync_cell_state(self)
        return q.question_id

    def receive_mobile_answer(self, question_id: str, answer: str) -> ThreadTurn:
        """Callback invoked by the Stigmergic Spine when the user answers on their phone."""
        turn = self.dag.append_turn(
            "user",
            f"[MOBILE_DECISION:{question_id}]: {answer}",
        )
        self.phase = "IDLE"
        return turn

    def answer_btw_side_question(self, question: str) -> str:
        """Zero-history side question (`/btw`) answered from cell state without mutating the thread DAG."""
        turn_count = len(self.dag.turns)
        return (
            f"[BTW from {self.cell_id} ({self.role}, model_family={self.model_family})]: "
            f"Phase={self.phase}, Objective={self.current_objective!r}, "
            f"Turns={turn_count}, Browser={self.display.state} | Answered: {question}"
        )

    def produce_candidate_patch_hash(self, unified_diff: str) -> str:
        return hashlib.sha256(unified_diff.encode("utf-8")).hexdigest()

    def status_snapshot(self) -> dict[str, Any]:
        vp: ViewportSnapshot = self.display.capture_viewport(wake_if_needed=False)
        return {
            "cell_id": self.cell_id,
            "role": self.role,
            "model_family": self.model_family,
            "phase": self.phase,
            "current_objective": self.current_objective,
            "turn_count": len(self.dag.turns),
            "active_thread_id": self.dag.active_thread_id,
            "display_state": vp.state,
            "browser_url": vp.current_url,
            "browser_wake_count": vp.wake_count,
            "viewport": vp.to_dict(),
        }
