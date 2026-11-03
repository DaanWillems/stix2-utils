"""STIX Meta Objects other than Marking Definition (see stix2utils.marking)."""

from __future__ import annotations

import enum
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from stix2utils.common import Extensions, ExternalReference, GranularMarking, STIXObjectBase, Timestamp, is_before
from stix2utils.references import AnyRef, IdentityRef, MarkingRef

# RFC 5646 language tag (loose): primary subtag plus optional subtags.
_LANGUAGE_TAG_RE = r"^[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*$"


class _MetaObject(STIXObjectBase):
    """Properties shared by the versioned STIX Meta Objects below."""

    spec_version: Literal["2.1"] = "2.1"
    created: Timestamp
    modified: Timestamp
    revoked: bool | None = None
    labels: Annotated[list[str], Field(min_length=1)] | None = None
    external_references: Annotated[list[ExternalReference], Field(min_length=1)] | None = None
    object_marking_refs: Annotated[list[MarkingRef], Field(min_length=1)] | None = None
    granular_markings: Annotated[list[GranularMarking], Field(min_length=1)] | None = None

    @model_validator(mode="after")
    def _modified_not_before_created(self) -> Self:
        if not is_before(self.created, self.modified):
            msg = "modified MUST be later than or equal to created"
            raise ValueError(msg)
        return self


class ExtensionType(enum.StrEnum):
    NEW_SDO = "new-sdo"
    NEW_SCO = "new-sco"
    NEW_SRO = "new-sro"
    PROPERTY_EXTENSION = "property-extension"
    TOPLEVEL_PROPERTY_EXTENSION = "toplevel-property-extension"


class ExtensionDefinition(_MetaObject):
    type: Literal["extension-definition"] = "extension-definition"
    created_by_ref: IdentityRef
    name: str
    description: str | None = None
    schema_: str = Field(alias="schema")
    version: str
    extension_types: Annotated[list[ExtensionType], Field(min_length=1)]
    extension_properties: Annotated[list[str], Field(min_length=1)] | None = None

    @model_validator(mode="after")
    def _toplevel_properties(self) -> Self:
        if self.extension_properties is not None and ExtensionType.TOPLEVEL_PROPERTY_EXTENSION not in self.extension_types:
            msg = "extension_properties MUST only be used with a toplevel-property-extension"
            raise ValueError(msg)
        return self


class LanguageContent(_MetaObject):
    type: Literal["language-content"] = "language-content"
    created_by_ref: IdentityRef | None = None
    confidence: Annotated[int, Field(ge=0, le=100)] | None = None
    extensions: Extensions | None = None
    object_ref: AnyRef
    object_modified: Timestamp | None = None
    contents: Annotated[dict[Annotated[str, Field(pattern=_LANGUAGE_TAG_RE)], dict[str, Any]], Field(min_length=1)]
