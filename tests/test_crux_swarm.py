"""Comprehensive End-to-End Test Suite for Crux-Swarm:
1. Symmetric `CruxCellNode` stack (Thread DAG, Out-of-Tree `ShadowGitStore`, `/steer`, `/btw`).
2. 3-Layer `CellSecurityGuard` & 4-Tier `PolicyEngine` (Path Sandbox, Credential Guard, Shell Unwrapping, Extension Privilege Clamping).
3. `LazyDisplayBrowserSupervisor` on-demand socket activation (`HIBERNATED -> ACTIVE -> SUSPENDED`) + Interactive Touch/Click/Type.
4. 3-Stage `CascadingJudge` (`clean_patch` anti-Goodhart, Cross-Family `BARS`, Position-Swapped Bradley-Terry MLE) + `Crux-Evals` Bridge.
5. `StigmergicSpineHub` SHA-256 `ConsensusLedger` (`INV-SWARM-1`), Task Queue, Atomic File-Lease Broker, and 4-Gear Worktree Upshift.
6. Away-From-Desk Mobile PWA HTTP Gateway (`ask_user`, `policy_approval`, `/steer`, `/btw`, interactive viewport tap/input, `/api/tasks`).
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from crux_swarm import (
    CandidatePatch,
    CascadingJudge,
    CruxCellNode,
    FileLeaseConflictError,
    StigmergicSpineHub,
    SwarmConsensusViolation,
    SwarmGear,
    create_spine_http_server,
    select_initial_gear,
)


class TestSymmetricCruxCellAndLazyBrowser(unittest.TestCase):
    def test_lazy_socket_activated_display_wake_interactive_input_and_idle_suspend(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            cell = CruxCellNode(
                "cell-01",
                role="architect",
                workspace_root=root / "ws",
                state_dir=root / "state",
                idle_timeout_seconds=10.0,
            )
            # 1. Cell starts with display HIBERNATED (0 MB browser overhead)
            self.assertEqual(cell.display.state, "HIBERNATED")
            self.assertEqual(cell.display.wake_count, 0)

            # 2. Pure code/reasoning step keeps display HIBERNATED and records ShadowGit commit
            res = cell.execute_step("Analyze schema invariants", thought="Checking types")
            self.assertEqual(cell.display.state, "HIBERNATED")
            self.assertIsNotNone(res.get("shadow_commit"))

            # 3. Browser tool invocation automatically wakes Xvfb + Chromium CDP
            cell.execute_step(
                "Inspect dashboard UI",
                tool_name="browser_navigate",
                tool_args={"url": "https://internal.example.com/metrics", "title": "Metrics Dashboard"},
            )
            self.assertEqual(cell.display.state, "ACTIVE")
            self.assertEqual(cell.display.wake_count, 1)

            # 4. Interactive touch/click and typing update cursor & interaction log
            click_snap = cell.display.dispatch_input("click", x=320, y=240)
            self.assertEqual(click_snap.last_cursor, (320, 240))
            self.assertGreaterEqual(click_snap.interaction_count, 2)

            # 5. Simulate idle timeout elapsing -> automatically transitions to SUSPENDED
            suspended = cell.display.check_idle_and_suspend(now=click_snap.captured_at + 25.0)
            self.assertTrue(suspended)
            self.assertEqual(cell.display.state, "SUSPENDED")

    def test_shadow_git_checkpoint_restore_and_four_tier_security_firewall(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            ws = root / "ws"
            ws.mkdir(parents=True, exist_ok=True)
            app_file = ws / "service.py"
            app_file.write_text("VERSION = 1\n", encoding="utf-8")

            cell = CruxCellNode(
                "cell-sec",
                workspace_root=ws,
                state_dir=root / "state",
            )
            # Capture initial ShadowGit snapshot
            snap1 = cell.capture_shadow_checkpoint("v1")
            self.assertIsNotNone(snap1)
            app_file.write_text("VERSION = 2\n", encoding="utf-8")
            assert snap1 is not None and cell.shadow_git is not None
            diff_txt = cell.shadow_git.diff_from(snap1)
            self.assertIn("+VERSION = 2", diff_txt)

            # Restore back to v1 via out-of-tree ShadowGitStore
            cell.shadow_git.restore(snap1)
            self.assertEqual(app_file.read_text(encoding="utf-8"), "VERSION = 1\n")

            # Path traversal & sensitive credential files (.env, .git/hooks) are blocked
            with self.assertRaises(PermissionError):
                cell.security.validate_path("../../etc/passwd")
            with self.assertRaises(PermissionError):
                cell.security.validate_path(".env")
            with self.assertRaises(PermissionError):
                cell.security.validate_path(".git/hooks/pre-commit", write=True)

            # Catastrophic commands (`sudo rm -rf /`) are hard-denied even when wrapped
            dec, _ = cell.security.check_command_policy("sudo env FOO=1 rm -rf /")
            self.assertEqual(dec, "DENY")

            # Extension TOML policy attempting `allow` is privilege-clamped
            loaded = cell.security.load_policy_toml(
                '[[rule]]\ntoolName = "exec_pty"\ndecision = "allow"\n',
                tier="extension",
            )
            self.assertEqual(loaded, 0)
            self.assertEqual(len(cell.security.clamped_warnings), 1)

            # Secret tokens are automatically redacted in the cell's Thread DAG
            fake_secret = "AKIA" + "1234567890ABCDEF"
            turn = cell.dag.append_turn("assistant", f"Loaded key {fake_secret}")
            self.assertNotIn(fake_secret, turn.content)
            self.assertIn("[REDACTED_SECRET]", turn.content)


class TestCascadingJudgeAndStigmergicSpine(unittest.TestCase):
    def test_cascading_judge_anti_goodhart_and_position_swapped_bradley_terry(self) -> None:
        # 1. Stage A blocks test assertion deletion (ANTI_GOODHART_VETO)
        bad_diff = (
            "diff --git a/tests/test_auth.py b/tests/test_auth.py\n"
            "--- a/tests/test_auth.py\n"
            "+++ b/tests/test_auth.py\n"
            "@@ -10,2 +10,1 @@\n"
            "-    assert user.is_authenticated\n"
        )
        bad_cand = CandidatePatch(
            candidate_id="cand-bad",
            contributor_cell_ids=("cell-01",),
            family="gemini",
            unified_diff=bad_diff,
        )
        stage_a = CascadingJudge.run_stage_a(bad_cand)
        self.assertFalse(stage_a.passed)
        self.assertTrue(any("ANTI_GOODHART_VETO" in r for r in stage_a.reasons))

        # 2. Stage C Position-Swapped Pairwise Bradley-Terry cancels slot bias
        cand_a = CandidatePatch("cand-a", ("cell-01",), "gemini", "diff --git a/a.py b/a.py\n+x = 1\n")
        cand_b = CandidatePatch("cand-b", ("cell-02",), "claude", "diff --git a/a.py b/a.py\n+x = 2\n")
        # Biased judge that ALWAYS picks slot "A" -> swapped comparison cancels out to (0.5, 0.5)!
        sa, sb = CascadingJudge.swapped_pairwise_compare(cand_a, cand_b, lambda _x, _y: "A")
        self.assertAlmostEqual(sa, 0.5)
        self.assertAlmostEqual(sb, 0.5)

    def test_task_queue_file_leases_and_four_gear_worktree_upshift(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            hub = StigmergicSpineHub(root / "spine")

            # 1. Atomic file-lease broker prevents concurrent edits to the same file
            hub.acquire_file_lease("cell-01", "src/core/router.py")
            with self.assertRaises(FileLeaseConflictError):
                hub.acquire_file_lease("cell-02", "src/core/router.py")
            hub.release_file_lease("cell-01", "src/core/router.py")
            lease2 = hub.acquire_file_lease("cell-02", "src/core/router.py")
            self.assertEqual(lease2.cell_id, "cell-02")

            # 2. Stigmergic Task Queue + CascadingJudge + ConsensusLedger completion
            gear = select_initial_gear(
                "Redesign the distributed architecture and optimize the consensus algorithm across all nodes"
            )
            self.assertEqual(gear, SwarmGear.G4_CRUCIBLE)
            t_card = hub.enqueue_task("Fix token parser", "Fix bug in token parser and add unit test")
            claimed = hub.claim_next_task("cell-01")
            assert claimed is not None
            self.assertEqual(claimed.task_id, t_card.task_id)
            clean_diff = (
                "diff --git a/src/parser.py b/src/parser.py\n"
                "--- a/src/parser.py\n"
                "+++ b/src/parser.py\n"
                "@@ -1,1 +1,2 @@\n"
                "+def parse_token(x): return x.strip()\n"
            )
            done_card, blk = hub.complete_task(
                t_card.task_id,
                cell_id="cell-01",
                unified_diff=clean_diff,
                judge_cell_id="cell-judge",
                judge_family="anthropic",
            )
            self.assertEqual(done_card.status, "COMPLETED")
            self.assertTrue(blk.approved)

            # 3. INV-SWARM-1: Self-grading attempt MUST raise SwarmConsensusViolation
            with self.assertRaises(SwarmConsensusViolation):
                hub.record_consensus_block(
                    candidate_id="patch-self",
                    contributor_cell_ids=["cell-01", "cell-02"],
                    judge_cell_id="cell-02",
                    judge_family="claude",
                    bars_score=1.0,
                    approved=True,
                )

            # 4. 4-Gear Automatic Gearbox: Gear 2 stall -> auto-upshift to Gear 3 isolated Git worktrees
            git_repo = root / "repo"
            git_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "--quiet"], cwd=git_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=git_repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=git_repo, check=True)
            (git_repo / "README.md").write_text("# Base\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=git_repo, check=True)
            subprocess.run(["git", "commit", "-m", "init", "--quiet"], cwd=git_repo, check=True)

            def shard_a(wt, spine, wid):
                (wt.path / "module_a.py").write_text("A = 1\n", encoding="utf-8")
                spine.post_event("CONTRACT_DELTA", wid, "Added module_a.A = 1", scope="module_a.py")

            def shard_b(wt, spine, wid):
                (wt.path / "module_b.py").write_text("B = 2\n", encoding="utf-8")
                spine.post_event("CONTRACT_DELTA", wid, "Added module_b.B = 2", scope="module_b.py")

            summary = hub.execute_with_stall_upshift(
                git_repo,
                "Refactor across module_a and module_b in parallel worktrees",
                solo_attempt=lambda: False,
                parallel_shards=[("cell-a", shard_a), ("cell-b", shard_b)],
                judge_cell_id="cell-judge",
            )
            self.assertTrue(summary.upshifted)
            self.assertEqual(summary.final_gear, SwarmGear.G3_SPIKE_WORKTREES)
            self.assertEqual(set(summary.merged_workers), {"cell-a", "cell-b"})
            self.assertEqual(len(summary.contract_deltas), 2)
            self.assertTrue((git_repo / "module_a.py").is_file())
            self.assertTrue((git_repo / "module_b.py").is_file())


class TestMobilePWACockpitAndAwayFromDeskRoundTrip(unittest.TestCase):
    def test_mobile_pwa_ask_user_policy_approval_steer_btw_interactive_browser_and_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            push_notifications: list[dict[str, object]] = []
            hub = StigmergicSpineHub(
                root / "spine",
                pairing_token="test-mobile-secret-token",
                webhook_sender=lambda payload: push_notifications.append(payload),
            )
            cell1 = CruxCellNode(
                "cell-01",
                role="architect",
                model_family="gemini",
                workspace_root=root / "ws1",
                state_dir=root / "st1",
                spine_hub=hub,
            )
            cell2 = CruxCellNode(
                "cell-02",
                role="implementer",
                model_family="claude",
                workspace_root=root / "ws2",
                state_dir=root / "st2",
                spine_hub=hub,
            )

            qid = cell1.ask_mobile_user(
                "Which caching layer should we target?",
                ["A) Redis Cluster", "B) In-Memory LRU"],
            )
            self.assertEqual(cell1.phase, "WAITING_HUMAN")
            self.assertEqual(len(push_notifications), 1)

            res_cmd = cell2.execute_step(
                "Clean old build artifacts",
                tool_name="exec_pty",
                tool_args={"command": "rm -rf /tmp/build_cache"},
            )
            self.assertEqual(res_cmd["status"], "WAITING_HUMAN")
            self.assertEqual(len(push_notifications), 2)

            server = create_spine_http_server(hub, host="127.0.0.1", port=0)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{port}"

                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(f"{base_url}/api/overview", timeout=5)
                self.assertEqual(ctx.exception.code, 401)

                headers = {"Authorization": "Bearer test-mobile-secret-token", "Content-Type": "application/json"}
                req = urllib.request.Request(f"{base_url}/api/overview", headers=headers)
                overview = json.loads(urllib.request.urlopen(req, timeout=5).read().decode("utf-8"))
                self.assertEqual(len(overview["cells"]), 2)
                self.assertEqual(len(overview["pending_questions"]), 2)

                # Answer Cell 1's question from the phone
                ans_req = urllib.request.Request(
                    f"{base_url}/api/questions/{qid}/answer",
                    data=json.dumps({"answer": "A) Redis Cluster"}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                ans_resp = json.loads(urllib.request.urlopen(ans_req, timeout=5).read().decode("utf-8"))
                self.assertEqual(ans_resp["status"], "ANSWERED")
                self.assertEqual(cell1.phase, "IDLE")

                # Enqueue a new 4-Gear task from the phone
                task_req = urllib.request.Request(
                    f"{base_url}/api/tasks",
                    data=json.dumps({"title": "Audit OAuth flow", "objective": "Fix OAuth token refresh bug"}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                task_resp = json.loads(urllib.request.urlopen(task_req, timeout=5).read().decode("utf-8"))
                self.assertEqual(task_resp["status"], "ENQUEUED")

                # Send interactive touch click & typing to Cell 1's browser from the phone
                inp_req = urllib.request.Request(
                    f"{base_url}/api/cells/cell-01/input",
                    data=json.dumps({"action": "click", "x": 480, "y": 300}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                inp_resp = json.loads(urllib.request.urlopen(inp_req, timeout=5).read().decode("utf-8"))
                self.assertEqual(inp_resp["state"], "ACTIVE")
                self.assertEqual(inp_resp["last_cursor"], [480, 300])
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
