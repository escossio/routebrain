from __future__ import annotations

import json
from pathlib import Path

from app.services.routebrain_topology_view_contract import validate_topology_view_contract


EXAMPLE_PATH = Path("docs/examples/routebrain_topology_view_v0_1.example.json")


def _load_example() -> dict:
    return json.loads(EXAMPLE_PATH.read_text())


def test_example_is_valid():
    payload = _load_example()
    assert validate_topology_view_contract(payload) == []


def test_wrong_contract_is_rejected():
    payload = _load_example()
    payload["contract"] = "wrong.contract"
    errors = validate_topology_view_contract(payload)
    assert any("contract must be routebrain_topology_view.v0_1" in error for error in errors)


def test_invalid_node_type_is_rejected():
    payload = _load_example()
    payload["nodes"][0]["type"] = "invalid_type"
    errors = validate_topology_view_contract(payload)
    assert any("nodes[0].type must be a valid topology node type" in error for error in errors)


def test_link_with_missing_node_reference_is_rejected():
    payload = _load_example()
    payload["links"][0]["target"] = "missing-node"
    errors = validate_topology_view_contract(payload)
    assert any("links[0].target must reference an existing node id" in error for error in errors)


def test_group_with_missing_node_reference_is_rejected():
    payload = _load_example()
    payload["groups"][0]["nodes"] = ["missing-node"]
    errors = validate_topology_view_contract(payload)
    assert any("groups[0].nodes must reference existing node ids" in error for error in errors)


def test_empty_scope_statement_is_rejected():
    payload = _load_example()
    payload["scope_statement"] = "   "
    errors = validate_topology_view_contract(payload)
    assert any("scope_statement must be a non-empty string" in error for error in errors)


def test_non_boolean_link_flags_are_rejected():
    payload = _load_example()
    payload["links"][0]["observed"] = "yes"
    payload["links"][0]["inferred"] = "no"
    errors = validate_topology_view_contract(payload)
    assert any("links[0].observed must be a boolean" in error for error in errors)
    assert any("links[0].inferred must be a boolean" in error for error in errors)
