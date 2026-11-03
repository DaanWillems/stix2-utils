from __future__ import annotations

import enum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from stix2utils.common import Timestamp, VersionedObject, is_before
from stix2utils.references import AnyRef, SampleRef, SoftwareRef
from stix2utils.vocabs import (
    AttackMotivationOv,
    AttackResourceLevelOv,
    GroupingContextOv,
    IdentityClassOv,
    ImplementationLanguageOv,
    IndicatorTypeOv,
    IndustrySectorOv,
    InfrastructureTypeOv,
    MalwareCapabilitiesOv,
    MalwareResultOv,
    MalwareTypeOv,
    OpenVocab,
    PatternTypeOv,
    ProcessorArchitectureOv,
    RegionOv,
    ReportTypeOv,
    ThreatActorRoleOv,
    ThreatActorSophisticationOv,
    ThreatActorTypeOv,
    ToolTypeOv,
)


class STIXDomainObject(VersionedObject):
    """Common properties shared by all STIX 2.1 SDOs."""

    def should(self) -> list[str]:
        warnings = super().should()
        for kill_chain_phase in getattr(self, "kill_chain_phases", None) or []:
            warnings += kill_chain_phase.should()
        return warnings


class KillChainPhase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kill_chain_name: str
    phase_name: str

    def should(self) -> list[str]:
        warnings = []
        if not self.kill_chain_name.islower():
            warnings.append("kill_chain_name should be lowercase")
        if "_" in self.kill_chain_name or " " in self.kill_chain_name:
            warnings.append("kill_chain_name should not contain spaces or underscores")
        if not self.phase_name.islower():
            warnings.append("phase_name should be lowercase")
        if "_" in self.phase_name or " " in self.phase_name:
            warnings.append("phase_name should not contain spaces or underscores")
        return warnings


def _check_seen(first: str | None, last: str | None, first_name: str, last_name: str) -> None:
    if not is_before(first, last):
        msg = f"{last_name} cannot be before {first_name}"
        raise ValueError(msg)


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

    @model_validator(mode="after")
    def _not_last_before_first(self) -> Self:
        _check_seen(self.first_seen, self.last_seen, "first_seen", "last_seen")
        return self


class CourseOfAction(STIXDomainObject):
    type: Literal["course-of-action"] = "course-of-action"
    name: str
    description: str | None = None


class Grouping(STIXDomainObject):
    type: Literal["grouping"] = "grouping"
    context: Annotated[str, OpenVocab(GroupingContextOv)]
    object_refs: Annotated[list[AnyRef], Field(min_length=1)]
    name: str | None = None
    description: str | None = None


class Identity(STIXDomainObject):
    type: Literal["identity"] = "identity"
    name: str
    identity_class: Annotated[str, OpenVocab(IdentityClassOv)] | None = None
    description: str | None = None
    roles: Annotated[list[str], Field(min_length=1)] | None = None
    sectors: Annotated[list[str], Field(min_length=1), OpenVocab(IndustrySectorOv)] | None = None
    contact_information: str | None = None


class Indicator(STIXDomainObject):
    type: Literal["indicator"] = "indicator"
    indicator_types: Annotated[list[str], Field(min_length=1), OpenVocab(IndicatorTypeOv)] | None = None
    pattern: str
    pattern_type: Annotated[str, OpenVocab(PatternTypeOv)]
    valid_from: Timestamp
    name: str | None = None
    description: str | None = None
    pattern_version: str | None = None
    valid_until: Timestamp | None = None
    kill_chain_phases: Annotated[list[KillChainPhase], Field(min_length=1)] | None = None

    @model_validator(mode="after")
    def _until_after_from(self) -> Self:
        if not is_before(self.valid_from, self.valid_until, strict=True):
            msg = "valid_until MUST be greater than valid_from"
            raise ValueError(msg)
        return self

    def should(self) -> list[str]:
        warnings = super().should()
        if self.name is None:
            warnings.append("name is missing")
        if self.description is None:
            warnings.append("description is missing")
        return warnings


class Infrastructure(STIXDomainObject):
    type: Literal["infrastructure"] = "infrastructure"
    name: str
    description: str | None = None
    infrastructure_types: Annotated[list[str], Field(min_length=1), OpenVocab(InfrastructureTypeOv)] | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    kill_chain_phases: Annotated[list[KillChainPhase], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None

    @model_validator(mode="after")
    def _not_last_before_first(self) -> Self:
        _check_seen(self.first_seen, self.last_seen, "first_seen", "last_seen")
        return self


class IntrusionSet(STIXDomainObject):
    type: Literal["intrusion-set"] = "intrusion-set"
    name: str
    description: str | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    goals: Annotated[list[str], Field(min_length=1)] | None = None
    resource_level: Annotated[str, OpenVocab(AttackResourceLevelOv)] | None = None
    primary_motivation: Annotated[str, OpenVocab(AttackMotivationOv)] | None = None
    secondary_motivations: Annotated[list[str], Field(min_length=1), OpenVocab(AttackMotivationOv)] | None = None

    @model_validator(mode="after")
    def _not_last_before_first(self) -> Self:
        _check_seen(self.first_seen, self.last_seen, "first_seen", "last_seen")
        return self


Latitude = Annotated[float, Field(ge=-90, le=90)]
Longitude = Annotated[float, Field(ge=-180, le=180)]
Precision = Annotated[float, Field(ge=0)]


class Location(STIXDomainObject):
    type: Literal["location"] = "location"
    name: str | None = None
    description: str | None = None
    latitude: Latitude | None = None
    longitude: Longitude | None = None
    precision: Precision | None = None
    region: Annotated[str, OpenVocab(RegionOv)] | None = None
    country: str | None = None
    administrative_area: str | None = None
    city: str | None = None
    street_address: str | None = None
    postal_code: str | None = None

    @model_validator(mode="after")
    def _latitude_longitude(self) -> Self:
        if (self.latitude is None) != (self.longitude is None):
            msg = "latitude and longitude MUST both be present or both be absent"
            raise ValueError(msg)
        if self.precision is not None and self.latitude is None:
            msg = "precision MUST NOT be present unless latitude and longitude are present"
            raise ValueError(msg)
        if self.region is None and self.country is None and self.latitude is None:
            msg = "location MUST contain at least one of region, country, or latitude and longitude"
            raise ValueError(msg)
        return self


class Malware(STIXDomainObject):
    type: Literal["malware"] = "malware"
    is_family: bool
    name: str | None = None
    description: str | None = None
    malware_types: Annotated[list[str], Field(min_length=1), OpenVocab(MalwareTypeOv)] | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    kill_chain_phases: Annotated[list[KillChainPhase], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    operating_system_refs: Annotated[list[SoftwareRef], Field(min_length=1)] | None = None
    architecture_execution_envs: Annotated[list[str], Field(min_length=1), OpenVocab(ProcessorArchitectureOv)] | None = None
    implementation_languages: Annotated[list[str], Field(min_length=1), OpenVocab(ImplementationLanguageOv)] | None = None
    capabilities: Annotated[list[str], Field(min_length=1), OpenVocab(MalwareCapabilitiesOv)] | None = None
    sample_refs: Annotated[list[SampleRef], Field(min_length=1)] | None = None

    @model_validator(mode="after")
    def _validate_malware(self) -> Self:
        if self.is_family and self.name is None:
            msg = "name MUST be present when is_family is true"
            raise ValueError(msg)
        _check_seen(self.first_seen, self.last_seen, "first_seen", "last_seen")
        return self


class MalwareAnalysis(STIXDomainObject):
    type: Literal["malware-analysis"] = "malware-analysis"
    product: str
    version: str | None = None
    host_vm_ref: SoftwareRef | None = None
    operating_system_ref: SoftwareRef | None = None
    installed_software_refs: Annotated[list[SoftwareRef], Field(min_length=1)] | None = None
    configuration_version: str | None = None
    modules: Annotated[list[str], Field(min_length=1)] | None = None
    analysis_engine_version: str | None = None
    analysis_definition_version: str | None = None
    submitted: Timestamp | None = None
    analysis_started: Timestamp | None = None
    analysis_ended: Timestamp | None = None
    result_name: str | None = None
    result: Annotated[str, OpenVocab(MalwareResultOv)] | None = None
    analysis_sco_refs: Annotated[list[AnyRef], Field(min_length=1)] | None = None
    sample_ref: SampleRef | None = None

    @model_validator(mode="after")
    def _validate_analysis(self) -> Self:
        if self.result is None and self.analysis_sco_refs is None:
            msg = "malware analysis MUST contain at least one of result or analysis_sco_refs"
            raise ValueError(msg)
        _check_seen(self.analysis_started, self.analysis_ended, "analysis_started", "analysis_ended")
        return self


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
    number_observed: Annotated[int, Field(ge=1, le=999_999_999)]
    object_refs: Annotated[list[AnyRef], Field(min_length=1)] | None = None
    objects: Annotated[dict[str, Any], Field(min_length=1)] | None = None  # deprecated in 2.1 in favor of object_refs

    @model_validator(mode="after")
    def _validate_observed_data(self) -> Self:
        _check_seen(self.first_observed, self.last_observed, "first_observed", "last_observed")
        if (self.object_refs is None) == (self.objects is None):
            msg = "observed data MUST contain exactly one of object_refs or objects"
            raise ValueError(msg)
        return self


class OpinionEnum(enum.StrEnum):
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
    report_types: Annotated[list[str], Field(min_length=1), OpenVocab(ReportTypeOv)] | None = None
    published: Timestamp
    object_refs: Annotated[list[AnyRef], Field(min_length=1)]
    description: str | None = None


class ThreatActor(STIXDomainObject):
    type: Literal["threat-actor"] = "threat-actor"
    name: str
    threat_actor_types: Annotated[list[str], Field(min_length=1), OpenVocab(ThreatActorTypeOv)] | None = None
    description: str | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    roles: Annotated[list[str], Field(min_length=1), OpenVocab(ThreatActorRoleOv)] | None = None
    goals: Annotated[list[str], Field(min_length=1)] | None = None
    sophistication: Annotated[str, OpenVocab(ThreatActorSophisticationOv)] | None = None
    resource_level: Annotated[str, OpenVocab(AttackResourceLevelOv)] | None = None
    primary_motivation: Annotated[str, OpenVocab(AttackMotivationOv)] | None = None
    secondary_motivations: Annotated[list[str], Field(min_length=1), OpenVocab(AttackMotivationOv)] | None = None
    personal_motivations: Annotated[list[str], Field(min_length=1), OpenVocab(AttackMotivationOv)] | None = None

    @model_validator(mode="after")
    def _not_last_before_first(self) -> Self:
        _check_seen(self.first_seen, self.last_seen, "first_seen", "last_seen")
        return self


class Tool(STIXDomainObject):
    type: Literal["tool"] = "tool"
    name: str
    tool_types: Annotated[list[str], Field(min_length=1), OpenVocab(ToolTypeOv)] | None = None
    description: str | None = None
    aliases: Annotated[list[str], Field(min_length=1)] | None = None
    kill_chain_phases: Annotated[list[KillChainPhase], Field(min_length=1)] | None = None
    tool_version: str | None = None


class Vulnerability(STIXDomainObject):
    type: Literal["vulnerability"] = "vulnerability"
    name: str
    description: str | None = None
