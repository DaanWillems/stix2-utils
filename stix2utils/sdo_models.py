from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from stix2utils.common import Timestamp
from stix2utils.references import _UUID, AnyRef, IdentityRef, MarkingRef, SampleRef, SoftwareRef


class STIXDomainObject(BaseModel):
    """Common properties shared by all STIX 2.1 SDOs."""

    model_config = ConfigDict(extra="forbid")

    # Required common properties
    id: str = Field(..., pattern=rf"^[a-z0-9-]+--{_UUID}$")
    spec_version: Literal["2.1"] = "2.1"
    created: Timestamp
    modified: Timestamp

    # Optional common properties
    created_by_ref: IdentityRef | None = None
    revoked: bool | None = None
    labels: Annotated[list[str], Field(min_length=1)] | None = None
    confidence: Annotated[int, Field(ge=0, le=100)] | None = None
    lang: str | None = None
    external_references: list[dict] | None = None
    object_marking_refs: Annotated[list[MarkingRef], Field(min_length=1)] | None = None
    granular_markings: list[dict] | None = None
    extensions: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _id_prefix_matches_type(self) -> STIXDomainObject:
        expected = self.type
        prefix = self.id.split("--", 1)[0]
        if prefix != expected:
            msg = f"id prefix {prefix!r} does not match type {expected!r}"
            raise ValueError(msg)
        return self


class KillChainPhase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kill_chain_name: str
    phase_name: str


class AttackPattern(STIXDomainObject):
    type: Literal["attack-pattern"] = "attack-pattern"
    name: str
    description: str | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    kill_chain_phases: Annotated[list[KillChainPhase], Field(min_length=1)] | None = None


class Campaign(STIXDomainObject):
    type: Literal["campaign"] = "campaign"
    name: str
    description: str | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    objective: str | None = None


class CourseOfAction(STIXDomainObject):
    type: Literal["course-of-action"] = "course-of-action"
    name: str
    description: str | None = None


class Grouping(STIXDomainObject):
    type: Literal["grouping"] = "grouping"
    context: str
    object_refs: Annotated[list[AnyRef], Field(min_length=1)]
    name: str | None = None
    description: str | None = None


class Identity(STIXDomainObject):
    type: Literal["identity"] = "identity"
    name: str
    identity_class: str
    description: str | None = None
    roles: Annotated[list[str], Field(min_length=1)] | None = None
    sectors: Annotated[list[str], Field(min_length=1)] | None = None
    contact_information: str | None = None


class Indicator(STIXDomainObject):
    type: Literal["indicator"] = "indicator"
    indicator_types: Annotated[list[str], Field(min_length=1)] | None = None
    pattern: str
    pattern_type: str
    valid_from: str
    name: str | None = None
    description: str | None = None
    pattern_version: str | None = None
    valid_until: str | None = None
    kill_chain_phases: Annotated[list[KillChainPhase], Field(min_length=1)] | None = None


class Infrastructure(STIXDomainObject):
    type: Literal["infrastructure"] = "infrastructure"
    name: str
    description: str | None = None
    infrastructure_types: Annotated[list[str], Field(min_length=1)] | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    kill_chain_phases: Annotated[list[KillChainPhase], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None


class IntrusionSet(STIXDomainObject):
    type: Literal["intrusion-set"] = "intrusion-set"
    name: str
    description: str | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    goals: Annotated[list[str], Field(min_length=1)] | None = None
    resource_level: str | None = None
    primary_motivation: str | None = None
    secondary_motivations: Annotated[list[str], Field(min_length=1)] | None = None


class Location(STIXDomainObject):
    type: Literal["location"] = "location"
    name: str | None = None
    description: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    precision: float | None = None
    region: str | None = None
    country: str | None = None
    administrative_area: str | None = None
    city: str | None = None
    street_address: str | None = None
    postal_code: str | None = None


class Malware(STIXDomainObject):
    type: Literal["malware"] = "malware"
    is_family: bool
    name: str | None = None
    description: str | None = None
    malware_types: Annotated[list[str], Field(min_length=1)] | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    kill_chain_phases: Annotated[list[KillChainPhase], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    operating_system_refs: Annotated[list[SoftwareRef], Field(min_length=1)] | None = None
    architecture_execution_envs: Annotated[list[str], Field(min_length=1)] | None = None
    implementation_languages: Annotated[list[str], Field(min_length=1)] | None = None
    capabilities: Annotated[list[str], Field(min_length=1)] | None = None
    sample_refs: Annotated[list[SampleRef], Field(min_length=1)] | None = None


class MalwareAnalysis(STIXDomainObject):
    type: Literal["malware-analysis"] = "malware-analysis"
    product: str
    version: str | None = None
    host_vm_ref: SoftwareRef | None = None
    operating_system_ref: SoftwareRef | None = None
    installed_software_refs: list[SoftwareRef] | None = None
    configuration_version: str | None = None
    modules: Annotated[list[str], Field(min_length=1)] | None = None
    analysis_engine_version: str | None = None
    analysis_definition_version: str | None = None
    submitted: str | None = None
    analysis_started: str | None = None
    analysis_ended: str | None = None
    result_name: str | None = None
    result: str | None = None
    analysis_sco_refs: Annotated[list[AnyRef], Field(min_length=1)] | None = None
    sample_ref: SampleRef | None = None


class Note(STIXDomainObject):
    type: Literal["note"] = "note"
    content: str
    object_refs: Annotated[list[AnyRef], Field(min_length=1)]
    abstract: str | None = None
    authors: Annotated[list[str], Field(min_length=1)] | None = None


class ObservedData(STIXDomainObject):
    type: Literal["observed-data"] = "observed-data"
    first_observed: Timestamp
    last_observed: Timestamp
    number_observed: int
    object_refs: Annotated[list[AnyRef], Field(min_length=1)] | None = None
    objects: dict | None = None  # deprecated in 2.1 in favor of object_refs


class OpinionEnum(str, Enum):
    STRONGLY_DISAGREE = "strongly-disagree"
    DISAGREE = "disagree"
    NEUTRAL = "neutral"
    AGREE = "agree"
    STRONGLY_AGREE = "strongly-agree"


class Opinion(STIXDomainObject):
    type: Literal["opinion"] = "opinion"
    opinion: OpinionEnum
    object_refs: Annotated[list[AnyRef], Field(min_length=1)]
    explanation: str | None = None
    authors: Annotated[list[str], Field(min_length=1)] | None = None


class Report(STIXDomainObject):
    type: Literal["report"] = "report"
    name: str
    report_types: Annotated[list[str], Field(min_length=1)]
    published: str
    object_refs: Annotated[list[AnyRef], Field(min_length=1)]
    description: str | None = None


class ThreatActor(STIXDomainObject):
    type: Literal["threat-actor"] = "threat-actor"
    name: str
    threat_actor_types: Annotated[list[str], Field(min_length=1)]
    description: str | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    roles: Annotated[list[str], Field(min_length=1)] | None = None
    goals: Annotated[list[str], Field(min_length=1)] | None = None
    sophistication: str | None = None
    resource_level: str | None = None
    primary_motivation: str | None = None
    secondary_motivations: Annotated[list[str], Field(min_length=1)] | None = None
    personal_motivations: Annotated[list[str], Field(min_length=1)] | None = None


class Tool(STIXDomainObject):
    type: Literal["tool"] = "tool"
    name: str
    tool_types: Annotated[list[str], Field(min_length=1)]
    description: str | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    kill_chain_phases: list[KillChainPhase] | None = None
    tool_version: str | None = None


class Vulnerability(STIXDomainObject):
    type: Literal["vulnerability"] = "vulnerability"
    name: str
    description: str | None = None
