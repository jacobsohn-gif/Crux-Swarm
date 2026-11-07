# Crux-Swarm (`crux-swarm`)

**Next-Generation Symmetric `Crux-Cell` Container Runtime, Lazy Socket-Activated OS/Browser Supervisor, Stigmergic Spine & Mobile PWA Cockpit**

`Crux-Swarm` completes the **Crucible Trilogy**:
1. **[`Crucible` (`crux`)](https://github.com/jacobsohn-gif/Crucible):** Interactive thought-tracing coding & swarm kernel.
2. **[`Crux-Evals`](https://github.com/jacobsohn-gif/Crux-Evals):** Open-Protocol MCP & Hook Evaluator Bank (Deterministic, Blind BARS Judge, Adversarial Breaker).
3. **[`Crux-Swarm`](https://github.com/jacobsohn-gif/Crux-Swarm):** Symmetric `Crux-Cell` container architecture where **every agent in the swarm** runs with its own full stack (`SessionDAG` conversation threads, `ThoughtTraceLedger`, 3-Layer `SecurityFirewall`, `ShadowGit` worktree, `Crux-Evals`, and a socket-activated full OS desktop + browser) coordinated through a **Stigmergic Spine** and an **Away-From-Desk Mobile PWA Cockpit**.

---

## Architectural Highlights (Resolved via `/grill-me`)

### 1. Symmetric `Crux-Cell` Pod Topology (`crux_swarm/cell/node.py`)
Instead of thin worker processes sharing a single folder, every container (`containers/Containerfile.crux-cell`) is a complete **Symmetric `Crux-Cell` Pod** layered over a shared read-only Rocky Linux 9 STIG image:
- **Per-Cell Multi-Branch Thread DAG (`CellThreadDAG`):** Every agent maintains its own local conversation threads (`.jsonl`), thought traces, mid-turn `/steer` queue, and zero-history `/btw` responder.
- **Per-Cell 3-Layer Security (`CellSecurityGuard`):** Enforces workspace sandbox boundaries, automatic secret token redaction, and `PolicyEngine` rules that automatically escalate high-impact commands (`ASK_USER`) to your phone.

### 2. Lazy Socket-Activated Full OS Desktop & Browser (`LazyDisplayBrowserSupervisor`)
Running Xvfb + Window Manager + Chromium eagerly across 12 containers would waste 8–12 GB of idle RAM.
- Every `Crux-Cell` starts in `HIBERNATED` display mode (`<0.5s` boot, `0 MB` browser RAM).
- The moment an agent invokes a browser/GUI tool (`browser_navigate`, `gui_click`) **or** you tap **"Wake & Inspect"** in the Mobile PWA, `LazyDisplayBrowserSupervisor` wakes `Xvfb :99` + Chromium CDP (`:9222`) in `<300ms`.
- Automatically suspends the display & browser processes after `idle_timeout_seconds` while preserving the persistent Chromium profile on disk.

### 3. Local-First Cell + Shared Stigmergic Spine (`crux_swarm/spine/hub.py`)
- **Parameterized SQLite-WAL Blackboard:** Broadcasts `SPIKE`, `CONTRACT_DELTA`, `QUESTION_OPENED`, `STEER`, and `LEDGER_COMMIT` events across cells.
- **SHA-256 Hash-Chained `ConsensusLedger` (`INV-SWARM-1`):** Cryptographically verifies every block (`prev_hash -> entry_hash`) and strictly forbids any cell from judging its own contribution (`judge_cell_id not in contributor_cell_ids`).

### 4. Away-From-Desk Mobile PWA Cockpit (`crux_swarm/mobile/index.html` & `spine/server.py`)
- **1-Tap Decision Inbox:** Answer `ask_user` multiple-choice clarifications and approve/deny `PolicyEngine` commands from your phone.
- **Live Multi-Agent Thread & Thought-Trace Switcher:** Tap any `Crux-Cell` pill to inspect its live conversation turns, internal thoughts, and send mid-turn `/steer` or `/btw` side questions.
- **Live Browser/OS Viewport Inspector:** View the container's current desktop/browser frame remotely on your phone.
- **Push & Webhook Alerts:** Outbound webhook/push notifications fire immediately whenever a cell enters `WAITING_HUMAN`.

---

## Quickstart

```bash
# 1. Run the test suite
PYTHONPATH=. python3 -m unittest discover -s tests -v

# 2. Launch the Stigmergic Spine & Mobile PWA Gateway
PYTHONPATH=. python3 -m crux_swarm.cli spine --host 127.0.0.1 --port 8890

# 3. Or launch the multi-cell Podman/Docker swarm stack
podman-compose -f containers/podman-compose.swarm.yml up -d --build
```
