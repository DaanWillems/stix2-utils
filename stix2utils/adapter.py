from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from stix2utils.marking import MarkingDefinition
from stix2utils.references import _UUID
from stix2utils.sco_models import (
    URL,
    Artifact,
    AutonomousSystem,
    Directory,
    DomainName,
    EmailAddress,
    EmailMessage,
    File,
    IPv4Address,
    IPv6Address,
    MACAddress,
    Mutex,
    NetworkTraffic,
    Process,
    Software,
    UserAccount,
    WindowsRegistryKey,
    X509Certificate,
)
from stix2utils.sdo_models import (
    AttackPattern,
    Campaign,
    CourseOfAction,
    Grouping,
    Identity,
    Indicator,
    Infrastructure,
    IntrusionSet,
    Location,
    Malware,
    MalwareAnalysis,
    Note,
    ObservedData,
    Opinion,
    Report,
    ThreatActor,
    Tool,
    Vulnerability,
)
from stix2utils.sro_models import Relationship, Sighting

STIXObject = (
    AttackPattern
    | Campaign
    | CourseOfAction
    | Grouping
    | Identity
    | Indicator
    | Infrastructure
    | IntrusionSet
    | Location
    | Malware
    | MalwareAnalysis
    | Note
    | ObservedData
    | Opinion
    | Report
    | ThreatActor
    | Tool
    | Vulnerability
    | Artifact
    | AutonomousSystem
    | Directory
    | DomainName
    | EmailAddress
    | EmailMessage
    | File
    | IPv4Address
    | IPv6Address
    | MACAddress
    | Mutex
    | NetworkTraffic
    | Process
    | Software
    | URL
    | UserAccount
    | WindowsRegistryKey
    | X509Certificate
    | Relationship
    | Sighting
    | MarkingDefinition
)

SDO_SCO_SRO = Annotated[STIXObject, Field(discriminator="type")]
stix_adapter: TypeAdapter = TypeAdapter(SDO_SCO_SRO)


class Bundle(BaseModel):
    """STIX 2.1 Bundle: a transport container for STIX Objects (not itself a STIX Object)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["bundle"] = "bundle"
    id: str = Field(..., pattern=rf"^bundle--{_UUID}$")
    objects: Annotated[list[SDO_SCO_SRO], Field(min_length=1)] | None = None

    def should(self) -> list[str]:
        """Collect warnings from contained objects, plus bundle-level checks."""
        warnings: list[str] = []
        if not self.objects:
            return warnings

        seen: set[tuple[str, object]] = set()
        for i, obj in enumerate(self.objects):
            warnings.extend(f"objects.{i} ({obj.id}): {w}" for w in obj.should())

            # Several versions of one object (same id, different modified) are legal;
            # the exact same version appearing twice is almost certainly a mistake.
            key = (obj.id, getattr(obj, "modified", None))
            if key in seen:
                warnings.append(f"objects.{i}: duplicate of {obj.id} with the same 'modified' value")
            seen.add(key)

        return warnings


TopLevel = Annotated[STIXObject | Bundle, Field(discriminator="type")]
stix_toplevel_adapter: TypeAdapter = TypeAdapter(TopLevel)
