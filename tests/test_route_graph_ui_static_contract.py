from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ROOT / "app/static/route_graph.js",
    ROOT / "app/static/route_graph_workspace.js",
    ROOT / "app/static/traceroute_visual.js",
]


def test_route_graph_ui_static_bgp_contract_is_present_and_defensive():
    route_graph_js = (ROOT / "app/static/route_graph.js").read_text()
    workspace_js = (ROOT / "app/static/route_graph_workspace.js").read_text()
    traceroute_js = (ROOT / "app/static/traceroute_visual.js").read_text()

    for path in FILES:
        text = path.read_text()
        assert "bgp_evidence" in text
        assert "bgp_context" in text
        assert "IP privado/CGNAT: sem atribuição BGP direta." in text

    assert "context.status" not in route_graph_js or "context.status ||" in route_graph_js
    assert "context.reason" not in route_graph_js or "context.reason ||" in route_graph_js

    assert "context.status ||" in workspace_js
    assert "context.reason ||" in workspace_js
    assert "context.status" in traceroute_js
    assert "context.reason" in traceroute_js

