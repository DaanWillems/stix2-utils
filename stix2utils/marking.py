from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from stix2utils.common import Timestamp
from stix2utils.references import _UUID, IdentityRef, MarkingRef


class MarkingDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Required
    type: Literal["marking-definition"] = "marking-definition"
    id: str = Field(..., pattern=rf"^marking-definition--{_UUID}$")
    spec_version: Literal["2.1"] = "2.1"
    created: Timestamp

    # Optional
    name: str | None = None
    definition_type: Literal["statement", "tlp"] | None = None
    definition: dict[str, Any] | None = None

    created_by_ref: IdentityRef | None = None
    external_references: list[dict] | None = None
    object_marking_refs: Annotated[list[MarkingRef], Field(min_length=1)] | None = None
    granular_markings: list[dict] | None = None
    extensions: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _definition_pair(self) -> MarkingDefinition:
        if (self.definition_type is None) != (self.definition is None):
            msg = "definition_type and definition must both be present or both absent"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _definition_or_extension(self) -> MarkingDefinition:
        if self.definition_type is None and not self.extensions:
            msg = "either definition_type/definition or extensions must be present"
            raise ValueError(msg)
        return self

    def should(self) -> list[str]:
        return []

