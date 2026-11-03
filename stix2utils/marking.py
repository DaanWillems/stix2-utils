from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from stix2utils.common import Extensions, ExternalReference, GranularMarking, STIXObjectBase, Timestamp
from stix2utils.references import IdentityRef, MarkingRef


class MarkingDefinition(STIXObjectBase):
    # Required
    type: Literal["marking-definition"] = "marking-definition"
    spec_version: Literal["2.1"] = "2.1"
    created: Timestamp

    # Optional
    name: str | None = None
    definition_type: Literal["statement", "tlp"] | None = None
    definition: dict[str, Any] | None = None

    created_by_ref: IdentityRef | None = None
    external_references: Annotated[list[ExternalReference], Field(min_length=1)] | None = None
    object_marking_refs: Annotated[list[MarkingRef], Field(min_length=1)] | None = None
    granular_markings: Annotated[list[GranularMarking], Field(min_length=1)] | None = None
    extensions: Extensions | None = None

    @model_validator(mode="after")
    def _definition_pair(self) -> Self:
        if (self.definition_type is None) != (self.definition is None):
            msg = "definition_type and definition must both be present or both absent"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _definition_or_extension(self) -> Self:
        if self.definition_type is None and not self.extensions:
            msg = "either definition_type/definition or extensions must be present"
            raise ValueError(msg)
        return self
