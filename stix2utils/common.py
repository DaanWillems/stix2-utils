import re
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from stix2utils.references import _TYPE, _UUID, IdentityRef, MarkingRef
from stix2utils.vocabs import HashAlgorithmOv, OpenVocab, open_vocab_warnings

# Backwards-compatible alias; the vocabulary now lives in stix2utils.vocabs.
HashAlgorithm = HashAlgorithmOv


class ShouldError(Exception):
    pass


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

_TIMESTAMP_RE = (
    r"^\d{4}-\d{2}-\d{2}"  # YYYY-MM-DD
    r"T\d{2}:\d{2}:\d{2}"  # THH:mm:ss
    r"(?:\.\d+)?"  # optional .s+  (dot only if digits follow)
    r"Z$"  # mandatory UTC designator
)


def timestamp_key(value: str) -> tuple[datetime, str]:
    """Return a key that orders STIX timestamps chronologically.

    STIX timestamps may carry any number of fractional-second digits, so they
    cannot be compared as plain strings ('.' sorts before 'Z', which makes
    '...00.5Z' look earlier than '...00Z'). The key is the whole-second datetime
    plus the fractional digits with trailing zeros removed; comparing digit
    strings of that form lexically is equivalent to comparing the fractions.

    Raises ValueError if the value is not a real calendar date/time.
    """
    whole, _, fraction = value.removesuffix("Z").partition(".")
    return datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S"), fraction.rstrip("0")


def _check_timestamp(value: str) -> str:
    try:
        timestamp_key(value)
    except ValueError:
        msg = f"{value!r} is not a valid date and time"
        raise ValueError(msg) from None
    return value


Timestamp = Annotated[str, Field(pattern=_TIMESTAMP_RE), AfterValidator(_check_timestamp)]


def is_before(earlier: str | None, later: str | None, *, strict: bool = False) -> bool:
    """True unless both timestamps are present and `later` comes before `earlier`.

    With strict=True, equal timestamps also count as out of order.
    """
    if earlier is None or later is None:
        return True
    if strict:
        return timestamp_key(earlier) < timestamp_key(later)
    return timestamp_key(earlier) <= timestamp_key(later)


# ---------------------------------------------------------------------------
# Hex and hashes
# ---------------------------------------------------------------------------

# hex type: even number of lowercase hex characters
Hex = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})+$")]


# hash-algorithm-ov is an open vocabulary: other keys are allowed, but they must
# be 3-250 characters of a-z, A-Z, 0-9, hyphen or underscore.
_HASH_KEY_RE = re.compile(r"^[a-zA-Z0-9_-]{3,250}$")


def _check_hash_keys(value: dict[str, str]) -> dict[str, str]:
    for key in value:
        if not _HASH_KEY_RE.match(key):
            msg = f"hash key {key!r} must be a hash-algorithm-ov value or 3-250 characters of a-z, A-Z, 0-9, '-' or '_'"
            raise ValueError(msg)
    return value


Hashes = Annotated[
    dict[str, Annotated[str, Field(min_length=1)]],
    Field(min_length=1),
    AfterValidator(_check_hash_keys),
    OpenVocab(HashAlgorithmOv, keys=True),
]


# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------

# An extension key is the id of an extension definition, or (deprecated STIX 2.1
# custom extensions) a name starting with 'x-'.
_EXTENSION_KEY_RE = re.compile(rf"^(?:extension-definition--{_UUID}|x-[a-z0-9-]+)$")


def check_extension_key(key: str) -> None:
    if not _EXTENSION_KEY_RE.match(key):
        msg = f"extension key {key!r} must be an extension-definition id or start with 'x-'"
        raise ValueError(msg)


def _check_extension_keys(value: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    for key in value:
        check_extension_key(key)
    return value


Extensions = Annotated[dict[str, dict[str, Any]], AfterValidator(_check_extension_keys)]


class PredefinedExtensions(BaseModel):
    """Base for the 'extensions' property of SCOs with predefined extensions.

    Predefined extensions are declared as aliased fields on subclasses. Any
    other key must be an extension-definition id (or a deprecated 'x-' name);
    this catches misspellings like 'ntfs_ext' that would otherwise slip through
    unvalidated.
    """

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="after")
    def _check_extra_keys(self) -> Self:
        for key, value in (self.model_extra or {}).items():
            check_extension_key(key)
            if not isinstance(value, dict):
                msg = f"extension {key!r} must be an object"
                raise ValueError(msg)  # noqa: TRY004 - pydantic expects ValueError
        return self


# ---------------------------------------------------------------------------
# Common data types
# ---------------------------------------------------------------------------


class ExternalReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_name: str
    description: str | None = None
    url: str | None = None
    hashes: Hashes | None = None
    external_id: str | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> Self:
        if self.description is None and self.url is None and self.external_id is None:
            msg = "external reference MUST contain at least one of description, url or external_id"
            raise ValueError(msg)
        return self


class GranularMarking(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lang: str | None = None
    marking_ref: MarkingRef | None = None
    selectors: Annotated[list[str], Field(min_length=1)]

    @model_validator(mode="after")
    def _lang_xor_marking_ref(self) -> Self:
        if (self.lang is None) == (self.marking_ref is None):
            msg = "granular marking MUST contain exactly one of lang or marking_ref"
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# Common bases
# ---------------------------------------------------------------------------

_ID_RE = re.compile(rf"^(?P<type>{_TYPE})--{_UUID}$")


class STIXObjectBase(BaseModel):
    """Properties and checks shared by every STIX object."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., pattern=rf"^{_TYPE}--{_UUID}$")
    type: str

    @model_validator(mode="after")
    def _id_prefix_matches_type(self) -> Self:
        match = _ID_RE.match(self.id)
        prefix = match["type"] if match else self.id.split("--", 1)[0]
        if prefix != self.type:
            msg = f"id prefix {prefix!r} does not match type {self.type!r}"
            raise ValueError(msg)
        return self

    def should(self) -> list[str]:
        return open_vocab_warnings(self)


class VersionedObject(STIXObjectBase):
    """Common properties of versioned objects (SDOs and SROs)."""

    # Required common properties
    spec_version: Literal["2.1"] = "2.1"
    created: Timestamp
    modified: Timestamp

    # Optional common properties
    created_by_ref: IdentityRef | None = None
    revoked: bool | None = None
    labels: Annotated[list[str], Field(min_length=1)] | None = None
    confidence: Annotated[int, Field(ge=0, le=100)] | None = None
    lang: str | None = None
    external_references: Annotated[list[ExternalReference], Field(min_length=1)] | None = None
    object_marking_refs: Annotated[list[MarkingRef], Field(min_length=1)] | None = None
    granular_markings: Annotated[list[GranularMarking], Field(min_length=1)] | None = None
    extensions: Extensions | None = None

    @model_validator(mode="after")
    def _modified_not_before_created(self) -> Self:
        if not is_before(self.created, self.modified):
            msg = "modified MUST be later than or equal to created"
            raise ValueError(msg)
        return self


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
