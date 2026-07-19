from typing import Annotated, TypeAlias

from pydantic import Field

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _pattern(*types: str) -> str:
    """Build the id-regex for one or more STIX id prefixes."""
    prefix = types[0] if len(types) == 1 else "(?:" + "|".join(types) + ")"
    return rf"^{prefix}--{_UUID}$"


# Single-type references
IdentityRef: TypeAlias = Annotated[str, Field(pattern=_pattern("identity"))]
MarkingRef: TypeAlias = Annotated[str, Field(pattern=_pattern("marking-definition"))]
SoftwareRef: TypeAlias = Annotated[str, Field(pattern=_pattern("software"))]
ObservedDataRef: TypeAlias = Annotated[str, Field(pattern=_pattern("observed-data"))]

# Multi-type references
SampleRef: TypeAlias = Annotated[str, Field(pattern=_pattern("file", "artifact"))]  # malware / malware-analysis samples
IdentityOrLocationRef: TypeAlias = Annotated[str, Field(pattern=_pattern("identity", "location"))]  # malware / malware-analysis samples
InstalledSoftwareRef: TypeAlias = Annotated[str, Field(pattern=_pattern("software"))]

# Open reference: any valid STIX object id (SDO / SCO / SRO / SMO)
AnyRef: TypeAlias = Annotated[str, Field(pattern=_pattern("[a-z0-9-]+"))]


# Single-type references
ArtifactRef: TypeAlias = Annotated[str, Field(pattern=_pattern("artifact"))]
AutonomousSystemRef: TypeAlias = Annotated[str, Field(pattern=_pattern("autonomous-system"))]
DirectoryRef: TypeAlias = Annotated[str, Field(pattern=_pattern("directory"))]
FileRef: TypeAlias = Annotated[str, Field(pattern=_pattern("file"))]
MACAddrRef: TypeAlias = Annotated[str, Field(pattern=_pattern("mac-addr"))]
NetworkTrafficRef: TypeAlias = Annotated[str, Field(pattern=_pattern("network-traffic"))]
ProcessRef: TypeAlias = Annotated[str, Field(pattern=_pattern("process"))]
UserAccountRef: TypeAlias = Annotated[str, Field(pattern=_pattern("user-account"))]

# Multi-type references
DirectoryContainsRef: TypeAlias = Annotated[str, Field(pattern=_pattern("file", "directory"))]
DomainResolvesToRef: TypeAlias = Annotated[str, Field(pattern=_pattern("ipv4-addr", "ipv6-addr", "domain-name"))]
IPResolvesToRef: TypeAlias = Annotated[str, Field(pattern=_pattern("mac-addr"))]
IPBelongsToRef: TypeAlias = Annotated[str, Field(pattern=_pattern("autonomous-system"))]
EmailAddrRef: TypeAlias = Annotated[str, Field(pattern=_pattern("email-addr"))]
EmailFromRef: TypeAlias = Annotated[str, Field(pattern=_pattern("email-addr"))]
MimeBodyRawRef: TypeAlias = Annotated[str, Field(pattern=_pattern("artifact", "file"))]
NetworkSrcDstRef: TypeAlias = Annotated[str, Field(pattern=_pattern("ipv4-addr", "ipv6-addr", "mac-addr", "domain-name"))]
