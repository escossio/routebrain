from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.route_graph_reporting import build_route_graph_report_for_run, render_route_graph_report_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Gera relatório local de completude do RouteGraph v1.")
    parser.add_argument("run_uid", help="Identificador da run, por exemplo etr-cloudflare-aabdb6c044184830")
    parser.add_argument("--format", choices={"json", "text"}, default="json")
    args = parser.parse_args()

    try:
        report = build_route_graph_report_for_run(args.run_uid)
    except ValueError as exc:
        print(json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False, indent=2))
        return 1
    if args.format == "text":
        print(render_route_graph_report_text(report))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
