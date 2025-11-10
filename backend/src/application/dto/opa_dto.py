"""OPA decision log data transfer objects."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class OPAInputAttributes(BaseModel):
    """OPA input attributes from Envoy ext_authz."""

    request: dict[str, Any] = Field(default_factory=dict)
    source: dict[str, Any] = Field(default_factory=dict)
    destination: dict[str, Any] = Field(default_factory=dict)


class OPAInput(BaseModel):
    """OPA decision input."""

    attributes: OPAInputAttributes
    parsed_path: list[str] = Field(default_factory=list)
    parsed_query: dict[str, list[str]] = Field(default_factory=dict)


class OPADecisionLog(BaseModel):
    """OPA decision log entry.

    Matches the format sent by OPA's decision_logs plugin.
    See: https://www.openpolicyagent.org/docs/latest/management-decision-logs/
    """

    decision_id: str = Field(..., description="Unique decision identifier")
    timestamp: datetime = Field(..., description="Decision timestamp")

    # Input to the policy
    input: OPAInput = Field(..., description="Input to policy evaluation")

    # Result of the policy evaluation
    result: dict[str, Any] = Field(default_factory=dict, description="Policy result")

    # Path to the policy rule
    path: str = Field(..., description="Policy path evaluated")

    # Optional fields
    requested_by: str | None = Field(None, description="Requester identity")
    labels: dict[str, str] = Field(default_factory=dict, description="Decision labels")
    metrics: dict[str, Any] = Field(default_factory=dict, description="Performance metrics")

    # Envoy-specific metadata
    envoy_metadata: dict[str, Any] | None = Field(None, alias="metadata")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class OPADecisionBatch(BaseModel):
    """Batch of OPA decision logs."""

    decisions: list[OPADecisionLog] = Field(default_factory=list)
