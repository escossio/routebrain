#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.route_memory import build_route_memory_report
from app.services.route_memory_graph_export import build_route_memory_graph_payload
from app.services.route_memory_persistence import load_route_memory_report, save_route_memory_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Register a persisted RouteMemory observation without running traceroute.")
    parser.add_argument("--source-node", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--resolved-ip")
    parser.add_argument("--measurement-id", type=int)
    parser.add_argument("--observation-uid", action="append", dest="observation_uids")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--graph", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = build_route_memory_report(args.target, resolved_ip=args.resolved_ip, measurement_id=args.measurement_id)
    graph_reports = [report]
    if args.graph and args.observation_uids:
        for observation_uid in args.observation_uids:
            loaded_report = load_route_memory_report(observation_uid)
            if loaded_report:
                graph_reports.append(loaded_report)
    graph_payload = build_route_memory_graph_payload(graph_reports, source_node=args.source_node) if args.graph else None
    result = {"report": report, "graph": graph_payload}
    if args.save:
        result["persistence"] = save_route_memory_report(report, source_node=args.source_node, graph_payload=graph_payload)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return
    print(f"target: {report.get('target')}")
    print(f"knowledge_status: {report.get('knowledge_status')}")
    if args.save:
        print(f"saved: {result['persistence']}")
    if graph_payload:
        print(f"graph_schema: {graph_payload.get('schema')}")


if __name__ == "__main__":
    main()
