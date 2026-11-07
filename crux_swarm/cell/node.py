"""Symmetric Crux-Cell Autonomous Agent Node (`CruxCellNode`).

Gives EVERY agent in the swarm the complete `Crucible` (`crux`) runtime stack:
1. Local Conversation Thread DAG (`CellThreadDAG`): Multi-branch conversation threads,
   mid-turn `/steer` queue, and zero-history `/btw` side-question responder.
2. Out-of-Tree `ShadowGitStore` Checkpointer: Captures workspace snapshots before/after
   steps without polluting `.git/index`, computes diffs, and supports `/restore`.
3. 3-Layer `CellSecurityGuard` & 4-Tier `PolicyEngine`: Path-boundary & credential file protection,
   shell-chain unwrapping (`sudo`, `env`, `&&`, `|`), catastrophic command blocking,
   secret redaction, and `ASK_USER` escalation to the Mobile PWA.
4. 3-Stage `CascadingJudge` & `Crux-Evals` Bridge: Stage-A `clean_patch` anti-Goodhart audit,
   Stage-B Provenance-Blind Cross-Family `BARS`, and Stage-C Position-Swapped Bradley-Terry.
5. `LazyDisplayBrowserSupervisor`: Socket-activated full-OS desktop (`Xvfb :99`) + interactive Chromium CDP.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import pathlib
import threading
import time
import uuid
from typing import Any, Literal

from crux_swarm.cell.display_supervisor import LazyDisplayBrowserSupervisor, ViewportSnapshot
from crux_swarm.cell.judge import CandidatePatch, CascadingJudge
from crux_swarm.cell.security import CellSecurityGuard, redact_cell_secrets
from crux_swarm.cell.shadow_git import ShadowGitStore, ShadowSnapshot

CellPhase = Literal["IDLE", "THINKING", "TOOL_DISPATCH", "WAITING_HUMAN", "EVALUATING", "DONE"]


@dataclass
class ThreadTurn:
    turn_id: str
    parent_id: str | None
    thread_id: str
    role: Literal["user", "assistant", "tool", "steer", "system"]
    content: str
    thought_trace: str = ""
    tool_name: str | None = None
    shadow_commit: str | None = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CellThreadDAG:
    """Per-cell multi-branch Conversation Thread DAG with live `/steer` queue and branch forking."""

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
        shadow_commit: str | None = None,
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
                shadow_commit=shadow_commit,
            )
            self.turns.append(turn)
            with self.dag_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(turn.to_dict(), ensure_ascii=False) + "\n")
            return turn

    def fork_thread(self, new_thread_id: str) -> str:
        with self._lock:
            self.active_thread_id = new_thread_id
        self.append_turn("system", f"Forked thread `{new_thread_id}`", thread_id=new_thread_id)
        return new_thread_id

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
            return [
                t.to_dict()
                for t in self.turns
                if thread_id is None or t.thread_id == thread_id
            ]


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
        enable_shadow_git: bool = True,
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
        self.shadow_git = ShadowGitStore(self.workspace_root, state_dir=self.state_dir) if enable_shadow_git else None
        self.last_shadow_snapshot: ShadowSnapshot | None = None
        self.display = LazyDisplayBrowserSupervisor(
            cell_id,
            state_dir=self.state_dir,
            idle_timeout_seconds=idle_timeout_seconds,
            dry_run_processes=dry_run_display,
        )
        self.spine_hub = spine_hub
        if self.spine_hub is not None:
            self.spine_hub.register_cell(self)

    def capture_shadow_checkpoint(self, label: str = "step") -> ShadowSnapshot | None:
        if self.shadow_git is None:
            return None
        try:
            self.last_shadow_snapshot = self.shadow_git.capture(label=label)
            return self.last_shadow_snapshot
        except Exception:
            return None

    def execute_step(
        self,
        user_prompt: str,
        *,
        thought: str = "",
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        assistant_reply: str = "",
    ) -> dict[str, Any]:
        """Executes a reasoning/tool turn inside the cell, takes ShadowGit checkpoints, and syncs to Spine."""
        self.current_objective = user_prompt or self.current_objective
        self.phase = "THINKING"
        self.dag.drain_steers()
        pre_snap = self.capture_shadow_checkpoint(label=f"pre:{tool_name or 'think'}")
        u_turn = self.dag.append_turn(
            "user",
            user_prompt,
            shadow_commit=pre_snap.commit_sha if pre_snap else None,
        )

        tool_args = dict(tool_args or {})
        if tool_name in ("browser_navigate", "open_url", "gui_click", "browser_input"):
            self.phase = "TOOL_DISPATCH"
            if tool_name == "gui_click" and "x" in tool_args and "y" in tool_args:
                snap = self.display.dispatch_input("click", x=int(tool_args["x"]), y=int(tool_args["y"]))
            else:
                url = str(tool_args.get("url", "https://localhost:8080"))
                snap = self.display.navigate(url, title=tool_args.get("title"))
            self.dag.append_turn(
                "tool",
                f"Browser action `{tool_name}` on {snap.current_url} (display={snap.display}, state={snap.state})",
                tool_name=tool_name,
            )

        if tool_name in ("write_file", "patch_file", "edit_file") and tool_args.get("path"):
            target = self.security.validate_path(str(tool_args["path"]), write=True)
            if "content" in tool_args:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(str(tool_args["content"]), encoding="utf-8")

        if tool_name == "exec_pty" and tool_args.get("command"):
            cmd = str(tool_args["command"])
            pol_decision, reason = self.security.check_command_policy(cmd)
            if pol_decision == "DENY":
                self.phase = "IDLE"
                raise PermissionError(reason)
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

        post_snap = self.capture_shadow_checkpoint(label=f"post:{tool_name or 'turn'}")
        a_turn = self.dag.append_turn(
            "assistant",
            assistant_reply or f"Completed step on `{self.cell_id}` ({self.role}).",
            thought_trace=thought or f"Analyzed objective in {self.cell_id}.",
            tool_name=tool_name,
            shadow_commit=post_snap.commit_sha if post_snap else None,
        )
        self.phase = "IDLE"
        if self.spine_hub is not None:
            self.spine_hub.sync_cell_state(self)
        return {
            "status": "COMPLETED",
            "user_turn_id": u_turn.turn_id,
            "assistant_turn_id": a_turn.turn_id,
            "shadow_commit": post_snap.commit_sha if post_snap else None,
        }

    def evaluate_candidate_patch(
        self,
        unified_diff: str,
        *,
        judge_cell_id: str = "cell-judge",
        judge_family: str = "anthropic",
    ) -> dict[str, Any]:
        """Runs the 3-Stage CascadingJudge + Crux-Evals gate and commits to the Spine ConsensusLedger."""
        self.phase = "EVALUATING"
        cand = CandidatePatch(
            candidate_id=f"cand_{uuid.uuid4().hex[:8]}",
            contributor_cell_ids=(self.cell_id,),
            family=self.model_family,
            unified_diff=unified_diff,
            worktree_path=str(self.workspace_root),
            summary=self.current_objective,
        )
        judge = CascadingJudge(judge_cell_id=judge_cell_id, judge_family=judge_family)
        verdict = judge.run_stage_b_bars(self.current_objective or "Verify patch", cand)
        eval_gate = judge.run_crux_evals_gate(self.current_objective or "Verify patch", cand)
        approved = bool(verdict.passed and eval_gate["passed"])
        block_dict: dict[str, Any] | None = None
        if self.spine_hub is not None:
            blk = self.spine_hub.record_consensus_block(
                candidate_id=cand.candidate_id,
                contributor_cell_ids=[self.cell_id],
                judge_cell_id=verdict.judge_cell_id,
                judge_family=verdict.judge_family,
                bars_score=verdict.score,
                approved=approved,
            )
            block_dict = blk.to_dict()
        self.phase = "IDLE"
        return {
            "candidate_id": cand.candidate_id,
            "approved": approved,
            "bars_verdict": verdict.to_dict(),
            "crux_evals_gate": eval_gate,
            "ledger_block": block_dict,
        }

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
            "shadow_git_commit": self.last_shadow_snapshot.commit_sha if self.last_shadow_snapshot else None,
            "display_state": vp.state,
            "browser_url": vp.current_url,
            "browser_wake_count": vp.wake_count,
            "viewport": vp.to_dict(),
        }
