"""Comprehensive End-to-End Test Suite for Crux-Swarm:
1. Symmetric `CruxCellNode` stack (Thread DAG, Secret Redaction, Security Sandbox, `/steer`, `/btw`).
2. `LazyDisplayBrowserSupervisor` on-demand socket activation (`HIBERNATED -> ACTIVE -> SUSPENDED`).
3. `StigmergicSpineHub` SHA-256 `ConsensusLedger` chain verification & `INV-SWARM-1` anti-self-grading.
4. Away-From-Desk Mobile PWA HTTP Gateway (`ask_user` & `policy_approval` round-trip, `/steer`, `/btw`, viewport wake, and HMAC Bearer auth).
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from crux_swarm import (
    CruxCellNode,
    StigmergicSpineHub,
    SwarmConsensusViolation,
    create_spine_http_server,
)


class TestSymmetricCruxCellAndLazyBrowser(unittest.TestCase):
    def test_lazy_socket_activated_display_wake_and_idle_suspend(self) -> None:
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

            # 2. Pure code/reasoning step keeps display HIBERNATED
            cell.execute_step("Analyze schema invariants", thought="Checking types")
            self.assertEqual(cell.display.state, "HIBERNATED")

            # 3. Browser tool invocation automatically wakes Xvfb + Chromium CDP
            cell.execute_step(
                "Inspect dashboard UI",
                tool_name="browser_navigate",
                tool_args={"url": "https://internal.example.com/metrics", "title": "Metrics Dashboard"},
            )
            self.assertEqual(cell.display.state, "ACTIVE")
            self.assertEqual(cell.display.wake_count, 1)
            snap = cell.display.capture_viewport()
            self.assertEqual(snap.current_url, "https://internal.example.com/metrics")
            self.assertTrue(snap.svg_data_uri.startswith("data:image/svg+xml;base64,"))

            # 4. Simulate idle timeout elapsing -> automatically transitions to SUSPENDED
            suspended = cell.display.check_idle_and_suspend(now=snap.captured_at + 25.0)
            self.assertTrue(suspended)
            self.assertEqual(cell.display.state, "SUSPENDED")

    def test_cell_security_firewall_and_secret_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            cell = CruxCellNode(
                "cell-sec",
                workspace_root=root / "ws",
                state_dir=root / "state",
            )
            # Path traversal outside cell workspace is blocked
            with self.assertRaises(PermissionError):
                cell.security.validate_path("../../etc/passwd")

            # Secret tokens are automatically redacted in the cell's Thread DAG
            fake_secret = "AKIA" + "1234567890ABCDEF"
            turn = cell.dag.append_turn("assistant", f"Loaded key {fake_secret}")
            self.assertNotIn(fake_secret, turn.content)
            self.assertIn("[REDACTED_SECRET]", turn.content)


class TestStigmergicSpineAndConsensusLedger(unittest.TestCase):
    def test_consensus_ledger_hash_chain_and_inv_swarm_1_anti_self_grading(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            hub = StigmergicSpineHub(pathlib.Path(tmpdir))

            # 1. Valid cross-cell consensus commits
            b1 = hub.record_consensus_block(
                candidate_id="patch-01",
                contributor_cell_ids=["cell-01"],
                judge_cell_id="cell-03",
                judge_family="openai",
                bars_score=0.92,
                approved=True,
            )
            b2 = hub.record_consensus_block(
                candidate_id="patch-02",
                contributor_cell_ids=["cell-02"],
                judge_cell_id="cell-01",
                judge_family="gemini",
                bars_score=0.88,
                approved=True,
            )
            self.assertEqual(b2.prev_hash, b1.entry_hash)
            valid, count = hub.verify_ledger_chain()
            self.assertTrue(valid)
            self.assertEqual(count, 2)

            # 2. INV-SWARM-1: Self-grading attempt MUST raise SwarmConsensusViolation
            with self.assertRaises(SwarmConsensusViolation):
                hub.record_consensus_block(
                    candidate_id="patch-self",
                    contributor_cell_ids=["cell-01", "cell-02"],
                    judge_cell_id="cell-02",
                    judge_family="claude",
                    bars_score=1.0,
                    approved=True,
                )


class TestMobilePWACockpitAndAwayFromDeskRoundTrip(unittest.TestCase):
    def test_mobile_pwa_ask_user_policy_approval_steer_btw_and_viewport_gateway(self) -> None:
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

            # Cell 1 asks a clarification question while user is away from desk
            qid = cell1.ask_mobile_user(
                "Which caching layer should we target?",
                ["A) Redis Cluster", "B) In-Memory LRU"],
            )
            self.assertEqual(cell1.phase, "WAITING_HUMAN")
            self.assertEqual(len(push_notifications), 1)
            self.assertEqual(push_notifications[0]["question_id"], qid)

            # Cell 2 attempts a high-risk command -> automatically escalates to Mobile Approval Queue
            res_cmd = cell2.execute_step(
                "Clean old build artifacts",
                tool_name="exec_pty",
                tool_args={"command": "rm -rf /tmp/build_cache"},
            )
            self.assertEqual(res_cmd["status"], "WAITING_HUMAN")
            self.assertEqual(len(push_notifications), 2)

            # Start the Stigmergic Spine HTTP Gateway on an ephemeral port
            server = create_spine_http_server(hub, host="127.0.0.1", port=0)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{port}"

                # 1. Verify unauthenticated API request is rejected (401)
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(f"{base_url}/api/overview", timeout=5)
                self.assertEqual(ctx.exception.code, 401)

                # 2. Verify PWA HTML shell is served
                html = urllib.request.urlopen(f"{base_url}/", timeout=5).read().decode("utf-8")
                self.assertIn("Crux-Swarm Cockpit", html)

                # 3. Fetch `/api/overview` with mobile pairing token
                headers = {"Authorization": "Bearer test-mobile-secret-token", "Content-Type": "application/json"}
                req = urllib.request.Request(f"{base_url}/api/overview", headers=headers)
                overview = json.loads(urllib.request.urlopen(req, timeout=5).read().decode("utf-8"))
                self.assertEqual(len(overview["cells"]), 2)
                self.assertEqual(len(overview["pending_questions"]), 2)

                # 4. Answer Cell 1's question from the phone with 1 tap
                ans_req = urllib.request.Request(
                    f"{base_url}/api/questions/{qid}/answer",
                    data=json.dumps({"answer": "A) Redis Cluster"}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                ans_resp = json.loads(urllib.request.urlopen(ans_req, timeout=5).read().decode("utf-8"))
                self.assertEqual(ans_resp["status"], "ANSWERED")
                self.assertEqual(cell1.phase, "IDLE")

                # 5. Send a live `/steer` and `/btw` from the phone to Cell 1
                steer_req = urllib.request.Request(
                    f"{base_url}/api/cells/cell-01/steer",
                    data=json.dumps({"text": "Prioritize p99 latency under 5ms"}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                urllib.request.urlopen(steer_req, timeout=5).read()

                btw_req = urllib.request.Request(
                    f"{base_url}/api/cells/cell-01/btw",
                    data=json.dumps({"question": "What is your current phase?"}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                btw_resp = json.loads(urllib.request.urlopen(btw_req, timeout=5).read().decode("utf-8"))
                self.assertIn("BTW from cell-01", btw_resp["reply"])

                # 6. Remotely wake & inspect Cell 1's OS/Browser Viewport from the phone (`?wake=1`)
                vp_req = urllib.request.Request(f"{base_url}/api/cells/cell-01/viewport?wake=1", headers=headers)
                vp_resp = json.loads(urllib.request.urlopen(vp_req, timeout=5).read().decode("utf-8"))
                self.assertEqual(vp_resp["state"], "ACTIVE")
                self.assertEqual(vp_resp["wake_count"], 1)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
