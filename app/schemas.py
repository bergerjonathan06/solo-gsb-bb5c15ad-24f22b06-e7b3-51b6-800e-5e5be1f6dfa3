"""Pydantic models for the HTTP API (pydantic v2)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .analyzer import ValidationError, normalize_action


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str = Field(..., description="IPv4/IPv6 network in CIDR notation; host bits must be zero")
    action: str = Field(..., description="permit/allow or deny/block/drop/reject")
    priority: int = Field(
        default=100, ge=0, description="Smaller number = higher priority; only breaks same-CIDR ties"
    )
    source_tag: str = Field(default="default", description="Label of the rule's origin")
    rule_id: str | None = Field(default=None, description="Optional unique id; auto-generated as r1, r2...")

    @field_validator("action")
    @classmethod
    def _normalize_action(cls, v: str) -> str:
        try:
            return normalize_action(v)
        except ValidationError as exc:
            # Pydantic turns ValueError into a 422 validation error response.
            raise ValueError(str(exc)) from exc

    @field_validator("cidr", "source_tag")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[RuleIn] = Field(..., min_length=1, description="Ordered rule set")
    name: str | None = Field(default=None, description="Optional human-readable version name")
    save: bool = Field(default=True, description="Persist this analysis as an immutable version")


class PatchRuleIn(RuleIn):
    """A rule participating in a simulate batch.

    Unlike :class:`RuleIn`, ``rule_id`` is mandatory: patch operations are
    addressed by it.
    """

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., description="Target/new rule id; add requires a new id, replace must hit the base")

    @field_validator("rule_id")
    @classmethod
    def _rule_id_nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("rule_id must not be empty")
        return v


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    add: list[PatchRuleIn] = Field(
        default_factory=list,
        description="Rules to add; each rule_id must be new (absent from the base version)",
    )
    replace: list[PatchRuleIn] = Field(
        default_factory=list,
        description="Whole-rule replacements; each rule_id must exist in the base version",
    )
    remove: list[str] = Field(
        default_factory=list,
        description="rule_ids to remove; each must exist in the base version"
    )

    @field_validator("remove")
    @classmethod
    def _remove_ids_nonempty(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        for rid in v:
            if not isinstance(rid, str) or not rid.strip():
                raise ValueError("remove entries must be non-empty rule_id strings")
            cleaned.append(rid.strip())
        return cleaned


class ListAnalysesResponse(BaseModel):
    total: int
    analyses: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
    errors: list[str] | None = Field(
        default=None,
        description="Full list of reasons when a request is rejected as a batch (e.g. simulate patch)",
    )
