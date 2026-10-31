from typing import Annotated

from pydantic import Field

from stix2utils.vocabs import HashAlgorithmOv

# Backwards-compatible alias; the vocabulary now lives in stix2utils.vocabs.
HashAlgorithm = HashAlgorithmOv


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
