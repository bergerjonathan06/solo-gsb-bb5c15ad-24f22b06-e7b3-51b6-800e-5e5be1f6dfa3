"""Rule-change simulation: rebuild a saved version's input and patch it.

The simulate endpoint takes a *saved* analysis version and a batch of
``add`` / ``replace`` / ``remove`` operations addressed by ``rule_id``:

* ``add``     : the rule_id must not exist in the base version;
* ``replace`` : the rule_id must exist in the base version.  A replace is a
  whole-rule overwrite (not a field merge), and the rule keeps its original
  position in the rule list;
* ``remove``  : the rule_id must exist in the base version.

Every rule_id may be addressed at most once across the whole batch, every
``add`` rule_id must be new, and every ``replace``/``remove`` target must
hit the base version.  Any violation rejects the *entire* batch; nothing is
applied or persisted.  Newly added rules are appended in request order, so
same-CIDR priority ties remain deterministic.

The patched input is re-analyzed from scratch by the regular LPM engine —
removing or replacing a subnet rule therefore naturally lets the closest
remaining ancestor win again on the uncovered addresses.
"""

from __future__ import annotations

from typing import Any

#: Input fields needed to rebuild an analyzer request, in canonical order.
_INPUT_FIELDS = ("rule_id", "cidr", "action", "priority", "source_tag")


class SimulationPatchError(Exception):
    """Raised when a simulate patch is structurally invalid.

    Carries every problem found in the batch so the API can reject it
    atomically with the full list of reasons.
    """

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def _base_rule_input(rule: dict[str, Any]) -> dict[str, Any]:
    """Rebuild one analyzer input rule from a saved analysis result row."""
    return {field: rule[field] for field in _INPUT_FIELDS}


def rebuild_input(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Reconstruct the original analyzer input from a stored result.

    Rows are taken in ``index`` order so the rebuilt list is byte-for-byte
    equivalent (modulo analysis) to the one that produced the saved version.
    """
    return [
        _base_rule_input(rule)
        for rule in sorted(result.get("rules", []), key=lambda r: r["index"])
    ]


def apply_patch(
    base_result: dict[str, Any],
    add: list[dict[str, Any]],
    replace: list[dict[str, Any]],
    remove: list[str],
) -> list[dict[str, Any]]:
    """Validate the batch against the base version and return patched rules.

    Raises :class:`SimulationPatchError` with *all* problems found when any
    operation is illegal; otherwise returns the rebuilt, patched rule list
    ready for :func:`app.analyzer.analyze_rules`.
    """
    errors: list[str] = []

    # ---- add rules: ids must be unique *inside the batch* ---------------
    add_by_id: dict[str, dict[str, Any]] = {}
    for rule in add:
        rid = rule["rule_id"]
        if rid in add_by_id:
            errors.append(f"add: rule_id {rid!r} appears more than once in the batch")
        else:
            add_by_id[rid] = rule

    # ---- replace rules: same, plus no overlap with remove ---------------
    replace_by_id: dict[str, dict[str, Any]] = {}
    for rule in replace:
        rid = rule["rule_id"]
        if rid in replace_by_id:
            errors.append(f"replace: rule_id {rid!r} appears more than once in the batch")
        else:
            replace_by_id[rid] = rule

    # ---- removes: unique strings, no overlap with replace --------------
    remove_seen: set[str] = set()
    remove_ids: list[str] = []
    for rid in remove:
        if rid in remove_seen:
            errors.append(f"remove: rule_id {rid!r} appears more than once in the batch")
            continue
        remove_seen.add(rid)
        remove_ids.append(rid)
        if rid in replace_by_id:
            errors.append(
                f"rule_id {rid!r} is targeted by both replace and remove; "
                "each rule may be changed at most once per simulation"
            )

    base_rules = rebuild_input(base_result)
    base_ids = {rule["rule_id"] for rule in base_rules}

    # ---- per-target legality against the base version -------------------
    for rid in add_by_id:
        if rid in base_ids:
            errors.append(
                f"add: rule_id {rid!r} already exists in the base version; "
                "added rules must use a new id (use 'replace' to change it)"
            )
    for rid in replace_by_id:
        if rid not in base_ids:
            errors.append(
                f"replace: rule_id {rid!r} does not exist in the base version; "
                "use 'add' for new rules"
            )
    for rid in remove_ids:
        if rid not in base_ids:
            errors.append(
                f"remove: rule_id {rid!r} does not exist in the base version"
            )

    if errors:
        raise SimulationPatchError(sorted(set(errors)))

    # ---- apply -----------------------------------------------------------
    patched: list[dict[str, Any]] = []
    for rule in base_rules:
        rid = rule["rule_id"]
        if rid in replace_by_id:
            # Whole-rule overwrite, keeping the original list position.
            patched.append(dict(replace_by_id[rid]))
        elif rid in remove_seen:
            continue
        else:
            patched.append(rule)
    # New rules are appended after the surviving base rules, in request order.
    patched.extend(dict(rule) for rule in add)

    if not patched:
        raise SimulationPatchError(
            ["patch removes every rule; a ruleset must contain at least one rule"]
        )
    return patched
