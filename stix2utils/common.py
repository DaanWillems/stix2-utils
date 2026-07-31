from enum import Enum
from typing import Annotated

from pydantic import Field


class ShouldError(Exception):
    pass


# ---------------------------------------------------------------------------
# Common base
# ---------------------------------------------------------------------------

_TIMESTAMP_RE = (
    r"^\d{4}-\d{2}-\d{2}"  # YYYY-MM-DD
    r"T\d{2}:\d{2}:\d{2}"  # THH:mm:ss
    r"(?:\.\d+)?"  # optional .s+  (dot only if digits follow)
    r"Z$"  # mandatory UTC designator
)

Timestamp = Annotated[str, Field(pattern=_TIMESTAMP_RE)]

# hex type: even number of lowercase hex characters
Hex = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})+$")]

# A hashes dictionary: keys are algorithm names, values are hash strings.
# Keys should come from hash-algorithm-ov, dictionary keys 3-250 ASCII chars.
Hashes = Annotated[dict[str, str], Field(min_length=1)]


class HashAlgorithm(str, Enum):
    MD5 = "MD5"
    SHA_1 = "SHA-1"
    SHA_256 = "SHA-256"
    SHA_512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"
    SSDEEP = "SSDEEP"
    TLSH = "TLSH"


# ---------------------------------------------------------------------------
# STIX object type universe
# ---------------------------------------------------------------------------

SDO_TYPES: frozenset[str] = frozenset(
    {
        "attack-pattern",
        "campaign",
        "course-of-action",
        "grouping",
        "identity",
        "incident",
        "indicator",
        "infrastructure",
        "intrusion-set",
        "location",
        "malware",
        "malware-analysis",
        "note",
        "observed-data",
        "opinion",
        "report",
        "threat-actor",
        "tool",
        "vulnerability",
    }
)

SCO_TYPES: frozenset[str] = frozenset(
    {
        "artifact",
        "autonomous-system",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "mutex",
        "network-traffic",
        "process",
        "software",
        "url",
        "user-account",
        "windows-registry-key",
        "x509-certificate",
    }
)
