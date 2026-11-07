"""Crux-Swarm CLI (`crux-swarm`, `crux-spine`, `crux-cell`)."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from crux_swarm.cell.node import CruxCellNode
from crux_swarm.spine.hub import StigmergicSpineHub
from crux_swarm.spine.server import create_spine_http_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="crux-swarm", description="Crux-Swarm Symmetric Container & Mobile Spine CLI")
    sub = parser.add_subparsers(dest="cmd")

    p_spine = sub.add_parser("spine", help="Start the Stigmergic Spine & Mobile PWA Gateway")
    p_spine.add_argument("--host", default="127.0.0.1", help="Bind host")
    p_spine.add_argument("--port", type=int, default=8890, help="Bind port")
    p_spine.add_argument("--state-dir", default=".crux_swarm/spine", help="State directory")
    p_spine.add_argument("--token", default=None, help="Optional fixed pairing token")

    p_cell = sub.add_parser("cell", help="Start a Symmetric Crux-Cell Agent Pod")
    p_cell.add_argument("--cell-id", default="cell-01", help="Unique cell ID")
    p_cell.add_argument("--role", default="generalist", help="Agent role")
    p_cell.add_argument("--family", default="gemini", help="Model family")
    p_cell.add_argument("--workspace", default=".crux_swarm/workspace", help="Cell workspace")
    p_cell.add_argument("--state-dir", default=".crux_swarm/cell", help="Cell state directory")
    p_cell.add_argument("--spine-url", default="http://127.0.0.1:8890", help="Stigmergic Spine URL")
    p_cell.add_argument("--port", type=int, default=8765, help="Cell local port")
    p_cell.add_argument("--status-only", action="store_true", help="Print cell snapshot JSON and exit")

    args = parser.parse_args(argv)

    if args.cmd == "spine":
        hub = StigmergicSpineHub(pathlib.Path(args.state_dir), pairing_token=args.token)
        srv = create_spine_http_server(hub, host=args.host, port=args.port)
        mobile_url = f"http://{args.host}:{args.port}/?token={hub.pairing_token}"
        sys.stdout.write(json.dumps({"status": "LISTENING", "mobile_pwa_url": mobile_url}, indent=2) + "\n")
        sys.stdout.flush()
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            srv.server_close()
        return 0

    if args.cmd == "cell":
        node = CruxCellNode(
            args.cell_id,
            role=args.role,
            model_family=args.family,
            workspace_root=pathlib.Path(args.workspace),
            state_dir=pathlib.Path(args.state_dir),
        )
        sys.stdout.write(json.dumps(node.status_snapshot(), indent=2) + "\n")
        return 0

    parser.print_help()
    return 0


def main_cell() -> int:
    return main(["cell", *sys.argv[1:]])


def main_spine() -> int:
    return main(["spine", *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
