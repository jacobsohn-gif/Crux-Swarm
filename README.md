# Crux-Swarm (`crux-swarm`)

**Next-Generation Symmetric `Crux-Cell` Container Runtime, 4-Gear Stigmergic Spine, 3-Stage Cascading Judge, Lazy Socket-Activated OS/Browser Supervisor & Mobile PWA Cockpit**

`Crux-Swarm` completes the **Crucible Trilogy**:
1. **[`Crucible` (`crux`)](https://github.com/jacobsohn-gif/Crucible):** Interactive thought-tracing coding & swarm kernel.
2. **[`Crux-Evals`](https://github.com/jacobsohn-gif/Crux-Evals):** Open-Protocol MCP & Hook Evaluator Bank (Deterministic, Blind BARS Judge, Adversarial Breaker).
3. **[`Crux-Swarm`](https://github.com/jacobsohn-gif/Crux-Swarm):** Symmetric `Crux-Cell` container architecture where **every agent in the swarm** runs with the complete `Crucible` stack (`CellThreadDAG` conversation threads, out-of-tree `ShadowGitStore`, 3-Layer `CellSecurityGuard` + 4-Tier `PolicyEngine`, 3-Stage `CascadingJudge` + `Crux-Evals`, and a socket-activated interactive OS desktop + browser) coordinated through a **4-Gear Stigmergic Spine** and an **Away-From-Desk Mobile PWA Cockpit**.

---

## Complete Feature Parity + Next-Gen Container & Mobile Upgrades

### 1. Symmetric `Crux-Cell` Pod (`crux_swarm/cell/`)
- **Multi-Branch Thread DAG (`CellThreadDAG`):** Local `.jsonl` conversation threads, branch forking (`fork_thread`), mid-turn `/steer` queue, and zero-history `/btw` responder.
- **Out-of-Tree `ShadowGitStore` & `GitWorktreePool` (`shadow_git.py`):** Captures pre/post-turn workspace snapshots using an out-of-tree `GIT_DIR` + `GIT_INDEX_FILE` (`core.hooksPath=/dev/null`) without touching `.git/index`, supports instant `restore()`, audits `clean_patch` for deleted test assertions (`ANTI_GOODHART_VETO`), and spawns isolated Git worktrees reconciled via `git merge-tree --write-tree`.
- **3-Layer Security Firewall & 4-Tier Policy Engine (`security.py`):** Workspace boundary enforcement, sensitive credential file blocking (`.env`, `*.pem`, `id_rsa`, `.git/hooks`), shell-chain unwrapping (`sudo`, `env`, `timeout`, `sh -c`, `&&`, `|`), catastrophic command blocking (`rm -rf /`, `mkfs`, forkbombs), child environment secret scrubbing (`scrub_child_environment`), and declarative TOML policies (`admin > user > workspace > extension`) with extension privilege clamping.
- **3-Stage `CascadingJudge` & `Crux-Evals` Bridge (`judge.py`):**
  - **Stage A ($0 Deterministic Sieve):** Audits `clean_patch` for test-assertion deletion, secret leaks, and optional test commands.
  - **Stage B (Provenance-Blind Cross-Family `BARS` Sentinel):** Evaluates `{0.0, 0.5, 1.0}` BARS anchors with multiplicative hard vetoes.
  - **Stage C (Position-Swapped `(A,B)` + `(B,A)` Pairwise Bradley-Terry MLE Tournament):** Eliminates LLM slot bias across competing worktree candidates.

### 2. Lazy Socket-Activated Interactive OS Desktop & Browser (`display_supervisor.py`)
- Every `Crux-Cell` starts in `HIBERNATED` mode (`<0.5s` boot, `0 MB` browser RAM).
- Wakes `Xvfb :99` + Chromium CDP (`:9222`) in `<300ms` on browser tool calls or Mobile PWA inspection.
- Supports **Interactive Mobile Touch-to-Click (`click`), Keyboard Typing (`type`), and URL Navigation (`navigate`)** directly from the Mobile PWA Cockpit, and auto-suspends after `idle_timeout_seconds`.

### 3. 4-Gear Stigmergic Spine, Task Queue & Consensus Ledger (`crux_swarm/spine/`)
- **4-Gear Automatic Gearbox (`G1_SOLO -> G2_STRIKE_PAIR -> G3_SPIKE_WORKTREES -> G4_CRUCIBLE`):** `execute_with_stall_upshift()` automatically upshifts stalled tasks into parallel Git worktree shards, broadcasts `CONTRACT_DELTA` events, checks 3-way merge cleanliness via `git merge-tree --write-tree`, and records cryptographic verdicts.
- **Stigmergic Task Queue & Atomic File-Lease Broker:** SQLite-WAL `swarm_tasks` and `file_leases` tables prevent concurrent file clobbering across cells.
- **SHA-256 Hash-Chained `ConsensusLedger` (`INV-SWARM-1`):** Cryptographically verifies every block (`prev_hash -> entry_hash`) and strictly forbids self-certification (`judge_cell_id not in contributor_cell_ids`).
- **Container Variants (`containers/`):** Includes both the standard Rocky Linux 9 STIG `Containerfile.crux-cell` and the internal Cloudtop/Argolis `Containerfile.crux-cell-googler` (`gcloud`, LOAS/BeyondCorp mounts).

---

## Quickstart

```bash
# 1. Run the full end-to-end test suite
PYTHONPATH=. python3 -m unittest discover -s tests -v

# 2. Launch the Stigmergic Spine & Mobile PWA Gateway
PYTHONPATH=. python3 -m crux_swarm.cli spine --host 127.0.0.1 --port 8890

# 3. Launch the multi-cell Podman/Docker swarm stack
podman-compose -f containers/podman-compose.swarm.yml up -d --build
```
