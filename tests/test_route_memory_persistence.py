from __future__ import annotations

from app.services import route_memory_persistence as persistence


class _FakeCursor:
    def __init__(self, state: dict[str, object]):
        self.state = state
        self.last_result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.state.setdefault("sql", []).append((sql, params))
        normalized = " ".join(sql.lower().split())
        if "from route_memory_observations where observation_uid" in normalized:
            self.last_result = self.state.get("existing_observation")
        elif normalized.startswith("insert into route_memory_observations"):
            self.last_result = [(self.state.setdefault("observation_id", 101),)]
            self.state["existing_observation"] = {"id": self.state["observation_id"], "observation_uid": params[0]}
        else:
            self.last_result = None

    def fetchone(self):
        if self.last_result is None:
            return None
        if isinstance(self.last_result, list):
            return self.last_result[0]
        return self.last_result

    def fetchall(self):
        return []


class _FakeConn:
    def __init__(self, state: dict[str, object]):
        self.state = state
        self.cursor_obj = _FakeCursor(state)

    def cursor(self, *args, **kwargs):
        return self.cursor_obj

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def commit(self):
        self.state["committed"] = True


def _fake_get_connection(state):
    return _FakeConn(state)


def _sample_report():
    return {
        "target": "example.com",
        "resolved_ip": "203.0.113.10",
        "tool": "mtr",
        "observed_at": "2026-06-23T10:00:00Z",
        "knowledge_status": "candidate",
        "route_known_fraction": 0.75,
        "summary": "synthetic",
        "raw_input_ref": {"measurement_id": 42},
        "hops": [
            {
                "hop_index": 1,
                "ip": "10.20.0.1",
                "raw_host": "gw",
                "hop_type": "local_lan",
                "is_private": True,
                "is_public": False,
                "confidence": "high",
                "evidence": {"kind": "synthetic"},
            }
        ],
        "observed_segments": [
            {
                "segment_type": "operator_private_core",
                "start_hop": 2,
                "end_hop": 4,
                "hop_count": 3,
                "contains_private": True,
                "contains_public": False,
                "contains_silent": False,
                "contains_mpls": False,
                "context_asn": None,
                "first_public_asn": None,
                "last_public_asn": None,
                "next_public_asn": None,
                "previous_public_asn": None,
                "rdns_signature": "core",
                "exact_fingerprint": "operator_private_core:10.21.0.1,10.21.0.2",
                "structural_fingerprint": "operator_private_core:core",
                "confidence": "medium",
                "state": "observed",
                "human_summary": "Private operator segment",
                "evidence": {"kind": "synthetic"},
            }
        ],
        "segment_matches": [
            {
                "observed_segment_uid": "known-observed",
                "known_segment_id": "known-operator_private_core",
                "match_type": "segment_match",
                "match_score": 80,
                "matched_hops_count": 3,
                "divergence_hop": None,
                "divergence_type": "private_branch_variation",
                "decision": "observe",
                "confidence": "medium",
                "evidence": ["operator_private_core"],
                "explanation": "synthetic",
            }
        ],
        "route_memory_events": [
            {
                "event_type": "segment_observed",
                "severity": "low",
                "old_value": None,
                "new_value": {"segment_type": "operator_private_core"},
                "explanation": "synthetic",
                "evidence": {"kind": "synthetic"},
                "observed_segment_uid": "known-observed",
            }
        ],
    }


def test_persist_route_memory_report_idempotent(monkeypatch):
    state = {}
    monkeypatch.setattr(persistence, "get_connection", lambda: _fake_get_connection(state))
    report = _sample_report()
    first = persistence.save_route_memory_report(report, source_node="example-server")
    second = persistence.save_route_memory_report(report, source_node="example-server")
    assert first["inserted"] is True
    assert second["inserted"] is False
    assert first["observation_uid"] == second["observation_uid"]


def test_persist_route_memory_report_records_children(monkeypatch):
    state = {}
    monkeypatch.setattr(persistence, "get_connection", lambda: _fake_get_connection(state))
    result = persistence.save_route_memory_report(_sample_report(), source_node="example-server")
    assert result["segments_inserted"] == 1
    assert result["hop_facts_inserted"] == 1
    assert result["matches_inserted"] == 1
    assert result["events_inserted"] == 1


def test_resolve_best_hop_facts_prefers_complete_latest_fact():
    hop_facts = [
        {
            "observation_uid": "rmo_test",
            "hop_index": 3,
            "ip": None,
            "hop_type": "unknown",
            "evidence": [],
            "source_measurement_id": 1,
        },
        {
            "observation_uid": "rmo_test",
            "hop_index": 3,
            "ip": "203.0.113.10",
            "hop_type": "public",
            "origin_asn": 64510,
            "bgp_prefix": "203.0.113.0/24",
            "evidence": ["bgp", "rdns"],
            "source_measurement_id": 2,
        },
    ]
    resolved = persistence.resolve_best_hop_facts(hop_facts)
    assert len(resolved) == 1
    assert resolved[0]["ip"] == "203.0.113.10"
    assert resolved[0]["hop_type"] == "public"
    assert resolved[0]["origin_asn"] == 64510


def test_resolve_best_hop_facts_keeps_incomplete_fact_when_alone():
    hop_facts = [
        {
            "observation_uid": "rmo_test",
            "hop_index": 4,
            "ip": None,
            "hop_type": "unknown",
            "evidence": [],
            "source_measurement_id": 1,
        }
    ]
    resolved = persistence.resolve_best_hop_facts(hop_facts)
    assert len(resolved) == 1
    assert resolved[0]["ip"] is None
    assert resolved[0]["hop_type"] == "unknown"
