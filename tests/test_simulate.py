"""End-to-end tests for the rule-change simulation endpoint.

POST /api/analyses/{id}/simulate
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-sim-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _save(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    body: dict = {"rules": rules}
    if name is not None:
        body["name"] = name
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    return r.json()["id"]


def _changes(payload: dict) -> dict[tuple[int, str], dict]:
    return {(c["ip_version"], c["change_type"]): c for c in payload["diff"]["changes"]}


# ---------------------------------------------------------------------------
# Ancestor revival: deleting / rewriting subnet rules
# ---------------------------------------------------------------------------
def test_remove_subnet_revives_ancestor_over_full_range(client: TestClient) -> None:
    # permit /8 (a) > deny /16 (b) > permit /24 (c).  Removing both children
    # must let a's permit take the whole /8 again, including the /16 that b
    # used to deny.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit"},
    ])

    r = client.post(f"/api/analyses/{aid}/simulate", json={"remove": ["b", "c"]})
    assert r.status_code == 200, r.text
    payload = r.json()

    # Base: /16 minus /24 denies (b effective), /24 permits (c), rest of /8 permits.
    # After removal a wins the whole /8: deny -> permit on b's old surface.
    by_type = _changes(payload)
    flipped = by_type[(4, "deny_to_permit")]
    assert flipped["address_count"] == 2 ** 16 - 2 ** 8
    # No permit-to-none: the union of matched space only shrank at the action
    # boundaries; a still covers everything.
    assert (4, "permit_to_none") not in by_type
    assert (4, "deny_to_none") not in by_type

    sim = payload["simulated"]
    a = next(rule for rule in sim["rules"] if rule["rule_id"] == "a")
    assert a["status"] == "active"
    assert a["effective_cidrs"] == ["10.0.0.0/8"]
    assert a["covered"] == 2 ** 24
    assert sim["summary"]["rule_count"] == 1
    assert sim["summary"]["partial_rules"] == 0


def test_rewrite_shrinking_subnet_revives_ancestor_fragment(client: TestClient) -> None:
    # permit /8, deny /24.  Rewrite the deny to one /25: the other /25 must
    # fall back to the ancestor's permit.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.1.0/24", "action": "deny"},
    ])

    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"replace": [
            {"rule_id": "b", "cidr": "10.1.1.0/25", "action": "deny", "priority": 100},
        ]},
    )
    assert r.status_code == 200, r.text
    by_type = _changes(r.json())
    revived = by_type[(4, "deny_to_permit")]
    assert revived["cidrs"] == ["10.1.1.128/25"]
    assert revived["address_count"] == 128
    # The surviving /25 keeps denying.
    assert (4, "permit_to_deny") not in by_type

    sim = r.json()["simulated"]
    b = next(rule for rule in sim["rules"] if rule["rule_id"] == "b")
    assert b["cidr"] == "10.1.1.0/25"
    assert b["status"] == "active"
    # a is partial again, covering the /8 minus the /25.
    a = next(rule for rule in sim["rules"] if rule["rule_id"] == "a")
    assert a["status"] == "partial"
    assert a["covered"] == 2 ** 24 - 2 ** 7


def test_replace_action_flip_changes_entire_effective_surface(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
    ])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"replace": [{"rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit"}]},
    )
    by_type = _changes(r.json())
    # The whole /16 flips to permit; the pair (b,a) disappears entirely.
    assert by_type[(4, "deny_to_permit")]["cidrs"] == ["10.1.0.0/16"]
    sim = r.json()["simulated"]
    assert sim["minimal_conflict_pairs"] == []
    a = next(rule for rule in sim["rules"] if rule["rule_id"] == "a")
    assert a["has_conflict"] is False


def test_remove_same_action_subnet_is_semantically_a_noop(client: TestClient) -> None:
    # A same-action child only reshapes rules, not forwarding.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit"},
    ])
    r = client.post(f"/api/analyses/{aid}/simulate", json={"remove": ["b"]})
    assert r.status_code == 200
    assert r.json()["diff"]["changes"] == []
    assert r.json()["diff"]["summary"]["total_changed_addresses"] == 0


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------
def test_add_new_rule_overrides_ancestor_and_uses_new_id(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
    ])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "new", "cidr": "10.2.0.0/23", "action": "deny", "source_tag": "trial"}]},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    by_type = _changes(payload)
    assert by_type[(4, "permit_to_deny")]["cidrs"] == ["10.2.0.0/23"]
    new_rule = next(rule for rule in payload["simulated"]["rules"] if rule["rule_id"] == "new")
    assert new_rule["source_tag"] == "trial"
    assert new_rule["index"] == 1  # appended after the surviving base rules
    old = next(rule for rule in payload["simulated"]["rules"] if rule["rule_id"] == "a")
    assert old["status"] == "partial"


def test_add_same_action_rule_does_not_change_semantics(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "new", "cidr": "10.2.0.0/24", "action": "permit"}]},
    )
    assert r.json()["diff"]["changes"] == []


def test_mixed_batch_is_applied_together(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit"},
    ])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={
            "add": [{"rule_id": "n", "cidr": "10.3.0.0/16", "action": "deny"}],
            "replace": [{"rule_id": "c", "cidr": "10.1.1.0/24", "action": "deny"}],
            "remove": ["a"],
        },
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["operations"] == {
        "add": ["n"],
        "replace": ["c"],
        "remove": ["a"],
    }
    ids = {rule["rule_id"] for rule in payload["simulated"]["rules"]}
    assert ids == {"b", "c", "n"}
    by_type = _changes(payload)
    # With a gone, addresses outside the deny /16s match no rule (permit -> none).
    permit_none = by_type[(4, "permit_to_none")]
    assert permit_none["address_count"] == 2 ** 24 - 2 * 2 ** 16
    # c flipped permit -> deny, n added deny under the (now removed) permit /8.
    permit_deny = by_type[(4, "permit_to_deny")]
    assert permit_deny["cidrs"] == ["10.1.1.0/24", "10.3.0.0/16"]
    assert permit_deny["address_count"] == 2 ** 8 + 2 ** 16


# ---------------------------------------------------------------------------
# Batch legality: any illegal op rejects everything
# ---------------------------------------------------------------------------
def test_add_existing_id_is_rejected(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
    ])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "a", "cidr": "10.2.0.0/24", "action": "deny"}]},
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_simulation_patch"
    assert len(body["errors"]) == 1
    assert "'a'" in body["errors"][0]


def test_replace_and_remove_unknown_ids_are_rejected(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={
            "replace": [{"rule_id": "ghost", "cidr": "10.2.0.0/24", "action": "deny"}],
            "remove": ["phantom"],
        },
    )
    assert r.status_code == 400
    messages = " ".join(r.json()["errors"])
    assert "'ghost'" in messages
    assert "'phantom'" in messages


def test_each_target_appears_at_most_once(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
    ])
    # same id in both replace and remove
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={
            "replace": [{"rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit"}],
            "remove": ["b"],
        },
    )
    assert r.status_code == 400
    assert any("both replace and remove" in e for e in r.json()["errors"])

    # duplicate id within one list
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"remove": ["a", "a"]},
    )
    assert r.status_code == 400
    assert any("appears more than once" in e for e in r.json()["errors"])


def test_multiple_problems_are_reported_together_and_nothing_applies(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={
            "add": [
                {"rule_id": "a", "cidr": "10.2.0.0/24", "action": "deny"},
                {"rule_id": "a", "cidr": "10.3.0.0/24", "action": "deny"},
            ],
            "remove": ["missing"],
        },
    )
    assert r.status_code == 400
    assert len(r.json()["errors"]) >= 2
    # The base version is untouched regardless of rejection.
    fetched = client.get(f"/api/analyses/{aid}").json()
    assert [rule["rule_id"] for rule in fetched["rules"]] == ["a"]


def test_invalid_rule_content_rejects_batch_with_400_invalid_ruleset(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
    ])
    # Host bits set in an otherwise correctly addressed replace.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"replace": [{"rule_id": "b", "cidr": "10.1.0.5/16", "action": "permit"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"
    assert "invalid CIDR" in r.json()["detail"]


def test_removing_every_rule_is_rejected(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
    ])
    r = client.post(f"/api/analyses/{aid}/simulate", json={"remove": ["a", "b"]})
    assert r.status_code == 400
    assert any("at least one rule" in e for e in r.json()["errors"])


def test_schema_errors_are_422(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"}])
    # PatchRuleIn requires rule_id.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"cidr": "10.2.0.0/24", "action": "deny"}]},
    )
    assert r.status_code == 422
    # Unknown action -> pydantic validation.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "n", "cidr": "10.2.0.0/24", "action": "maybe"}]},
    )
    assert r.status_code == 422
    # Extra fields are forbidden.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"bogus": []},
    )
    assert r.status_code == 422
    # Non-string remove entry.
    r = client.post(f"/api/analyses/{aid}/simulate", json={"remove": [42]})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Persistence / addressing
# ---------------------------------------------------------------------------
def test_simulation_is_never_persisted(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"}])
    before = client.get("/api/analyses").json()
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "n", "cidr": "10.2.0.0/24", "action": "deny"}]},
    )
    assert r.status_code == 200
    assert r.json()["simulated"]["persisted"] is False
    after = client.get("/api/analyses").json()
    assert after["total"] == before["total"] == 1
    # The trial ruleset hash must not resolve as a stored version.
    sim_hash = r.json()["simulated"]["ruleset_hash"]
    sim_id = "an_" + sim_hash[:16]
    assert client.get(f"/api/analyses/{sim_id}").status_code == 404
    # The base version itself is unchanged.
    assert client.get(f"/api/analyses/{aid}").json()["ruleset_hash"] != sim_hash


def test_empty_patch_is_a_noop_preview(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
    ])
    for body in ({}, {"add": [], "replace": [], "remove": []}):
        r = client.post(f"/api/analyses/{aid}/simulate", json=body)
        assert r.status_code == 200, r.text
        payload = r.json()
        assert payload["diff"]["changes"] == []
        assert payload["simulated"]["ruleset_hash"] == client.get(f"/api/analyses/{aid}").json()["ruleset_hash"]


def test_simulate_error_codes_for_unknown_base(client: TestClient) -> None:
    # Malformed id -> 400
    r = client.post("/api/analyses/not-an-id/simulate", json={})
    assert r.status_code == 400
    assert "invalid analysis id format" in r.json()["detail"]

    # Well-formed but missing -> 404
    r = client.post("/api/analyses/an_0000000000000000/simulate", json={})
    assert r.status_code == 404
    assert "an_0000000000000000" in r.json()["detail"]


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------
def test_ipv6_ancestor_revival_counts_are_exact(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "2001:db8::/32", "action": "deny"},
        {"rule_id": "b", "cidr": "2001:db8:1::/48", "action": "permit"},
    ])
    r = client.post(f"/api/analyses/{aid}/simulate", json={"remove": ["b"]})
    assert r.status_code == 200
    by_type = _changes(r.json())
    entry = by_type[(6, "permit_to_deny")]
    assert entry["cidrs"] == ["2001:db8:1::/48"]
    # 2**80 addresses — must stay an exact integer beyond 64-bit range.
    assert entry["address_count"] == 2 ** 80
    assert isinstance(entry["address_count"], int)
