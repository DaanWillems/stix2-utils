from typing import Annotated

from pydantic import Field, TypeAdapter

from stix2utils.sco_models import URL, Artifact, AutonomousSystem, Directory, DomainName, EmailAddress, EmailMessage, File, IPv4Address, IPv6Address, MACAddress, Mutex, NetworkTraffic, Process, Software, UserAccount, WindowsRegistryKey, X509Certificate
from stix2utils.sdo_models import AttackPattern, Campaign, CourseOfAction, Grouping, Identity, Indicator, Infrastructure, IntrusionSet, Location, Malware, MalwareAnalysis, Note, ObservedData, Opinion, Report, ThreatActor, Tool, Vulnerability
from stix2utils.sro_models import Relationship, Sighting


SDO_SCO = Annotated[
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
    | Sighting,
    Field(discriminator="type"),
]

stix_adapter = TypeAdapter(SDO_SCO)
