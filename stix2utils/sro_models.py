from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from stix2utils.common import SCO_TYPES, SDO_TYPES, Timestamp
from stix2utils.references import _UUID, AnyRef, IdentityOrLocationRef, IdentityRef, MarkingRef, ObservedDataRef

# relationship_type: ASCII a-z, 0-9, hyphen; no leading/trailing/double hyphen.
_RELATIONSHIP_TYPE_RE = r"^[a-z0-9]+(-[a-z0-9]+)*$"


# Endpoints (source_ref / target_ref) MUST be an SDO or SCO. They MUST NOT be an
# SRO, a Bundle, or an SMO (Language Content, Marking Definition, Extension
# Definition). See sections 5.1.2 and 5.2.1.
FORBIDDEN_ENDPOINT_TYPES: frozenset[str] = frozenset(
    {
        "relationship",
        "sighting",
        "bundle",
        "language-content",
        "marking-definition",
        "extension-definition",
    }
)

CORE_TYPES: frozenset[str] = SDO_TYPES | SCO_TYPES

# Common relationships defined for all SDOs/SCOs (section 3.7).
COMMON_RELATIONSHIPS: frozenset[str] = frozenset({"related-to", "duplicate-of", "derived-from"})
# derived-from / duplicate-of relate two objects of the *same* type.
_SAME_TYPE_COMMON: frozenset[str] = frozenset({"derived-from", "duplicate-of"})


# ---------------------------------------------------------------------------
# Specification-defined relationships
#
# Compiled from Appendix B (Relationship Summary Table) and reconciled with the
# authoritative per-SDO relationship tables in section 4 and the SCO-level
# relationships in section 6. Where Appendix B and an SDO's own table disagree,
# the SDO table wins (per section 5.1.1): e.g. `exfiltrates-to` (4.11.2) rather
# than Appendix B's `exfiltrate-to`, and course-of-action `remediates` (4.3.2)
# which Appendix B omits.
#
# Keyed by (source_type, relationship_type) -> allowed target types.
# ---------------------------------------------------------------------------

_ALL_SCO = set(SCO_TYPES)

ALLOWED_RELATIONSHIPS: dict[tuple[str, str], set[str]] = {
    # --- Attack Pattern ---
    ("attack-pattern", "delivers"): {"malware"},
    ("attack-pattern", "targets"): {"identity", "location", "vulnerability"},
    ("attack-pattern", "uses"): {"malware", "tool"},
    # --- Campaign ---
    ("campaign", "attributed-to"): {"intrusion-set", "threat-actor"},
    ("campaign", "compromises"): {"infrastructure"},
    ("campaign", "originates-from"): {"location"},
    ("campaign", "targets"): {"identity", "location", "vulnerability"},
    ("campaign", "uses"): {"attack-pattern", "infrastructure", "malware", "tool"},
    # --- Course of Action ---
    ("course-of-action", "investigates"): {"indicator"},
    ("course-of-action", "mitigates"): {
        "attack-pattern",
        "indicator",
        "malware",
        "tool",
        "vulnerability",
    },
    ("course-of-action", "remediates"): {"malware", "vulnerability"},
    # --- Identity ---
    ("identity", "located-at"): {"location"},
    # --- Indicator ---
    ("indicator", "indicates"): {
        "attack-pattern",
        "campaign",
        "infrastructure",
        "intrusion-set",
        "malware",
        "threat-actor",
        "tool",
    },
    ("indicator", "based-on"): {"observed-data"},
    # --- Infrastructure ---
    ("infrastructure", "communicates-with"): {
        "infrastructure",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
    },
    ("infrastructure", "consists-of"): {"infrastructure", "observed-data"} | _ALL_SCO,
    ("infrastructure", "controls"): {"infrastructure", "malware"},
    ("infrastructure", "delivers"): {"malware"},
    ("infrastructure", "has"): {"vulnerability"},
    ("infrastructure", "hosts"): {"tool", "malware"},
    ("infrastructure", "located-at"): {"location"},
    ("infrastructure", "uses"): {"infrastructure"},
    # --- Intrusion Set ---
    ("intrusion-set", "attributed-to"): {"threat-actor"},
    ("intrusion-set", "compromises"): {"infrastructure"},
    ("intrusion-set", "hosts"): {"infrastructure"},
    ("intrusion-set", "owns"): {"infrastructure"},
    ("intrusion-set", "originates-from"): {"location"},
    ("intrusion-set", "targets"): {"identity", "location", "vulnerability"},
    ("intrusion-set", "uses"): {"attack-pattern", "infrastructure", "malware", "tool"},
    # --- Malware ---
    ("malware", "authored-by"): {"threat-actor", "intrusion-set"},
    ("malware", "beacons-to"): {"infrastructure"},
    ("malware", "exfiltrates-to"): {"infrastructure"},
    ("malware", "communicates-with"): {"ipv4-addr", "ipv6-addr", "domain-name", "url"},
    ("malware", "controls"): {"malware"},
    ("malware", "downloads"): {"malware", "tool", "file"},
    ("malware", "drops"): {"malware", "tool", "file"},
    ("malware", "exploits"): {"vulnerability"},
    ("malware", "originates-from"): {"location"},
    ("malware", "targets"): {"identity", "infrastructure", "location", "vulnerability"},
    ("malware", "uses"): {"attack-pattern", "infrastructure", "malware", "tool"},
    ("malware", "variant-of"): {"malware"},
    # --- Malware Analysis ---
    ("malware-analysis", "characterizes"): {"malware"},
    ("malware-analysis", "av-analysis-of"): {"malware"},
    ("malware-analysis", "static-analysis-of"): {"malware"},
    ("malware-analysis", "dynamic-analysis-of"): {"malware"},
    # --- Threat Actor ---
    ("threat-actor", "attributed-to"): {"identity"},
    ("threat-actor", "compromises"): {"infrastructure"},
    ("threat-actor", "hosts"): {"infrastructure"},
    ("threat-actor", "owns"): {"infrastructure"},
    ("threat-actor", "impersonates"): {"identity"},
    ("threat-actor", "located-at"): {"location"},
    ("threat-actor", "targets"): {"identity", "location", "vulnerability"},
    ("threat-actor", "uses"): {"attack-pattern", "infrastructure", "malware", "tool"},
    # --- Tool ---
    ("tool", "delivers"): {"malware"},
    ("tool", "drops"): {"malware"},
    ("tool", "has"): {"vulnerability"},
    ("tool", "targets"): {"identity", "infrastructure", "location", "vulnerability"},
    ("tool", "uses"): {"infrastructure"},
    # --- SCO-level relationships (section 6, made external in 2.1) ---
    ("domain-name", "resolves-to"): {"domain-name", "ipv4-addr", "ipv6-addr"},
    ("ipv4-addr", "resolves-to"): {"mac-addr"},
    ("ipv4-addr", "belongs-to"): {"autonomous-system"},
    ("ipv6-addr", "resolves-to"): {"mac-addr"},
    ("ipv6-addr", "belongs-to"): {"autonomous-system"},
}

# The set of relationship_type strings the specification defines. A value in
# this set is validated against ALLOWED_RELATIONSHIPS; a value outside it is
# treated as user-defined and permitted between any SDO/SCO.
KNOWN_RELATIONSHIP_TYPES: frozenset[str] = frozenset(rt for (_src, rt) in ALLOWED_RELATIONSHIPS)


def _prefix(ref: str) -> str:
    return ref.split("--", 1)[0]


def check_relationship_endpoints(source_ref: str, target_ref: str, relationship_type: str) -> str | None:
    """Return an error string if the (source, type, target) triple is disallowed
    by the STIX 2.1 specification, otherwise None.

    Enforcement rules:
      * Endpoints MUST be an SDO or SCO (never an SRO/Bundle/SMO).
      * `related-to` is permitted between any two SDOs/SCOs.
      * `derived-from` / `duplicate-of` require identical source and target types.
      * A specification-defined relationship type (e.g. `uses`, `targets`) used
        between two *known core* object types MUST match an allowed
        source->type->target combination.
      * A user-defined relationship type (anything the spec does not define) is
        permitted between any two SDOs/SCOs.
      * If either endpoint is a custom/unknown type, the source->target
        combination is not checked (the spec only defines these relationships
        between its own object types).
    """
    src = _prefix(source_ref)
    tgt = _prefix(target_ref)

    if src in FORBIDDEN_ENDPOINT_TYPES:
        return f"source_ref must reference an SDO or SCO, not a {src!r} object"
    if tgt in FORBIDDEN_ENDPOINT_TYPES:
        return f"target_ref must reference an SDO or SCO, not a {tgt!r} object"

    rt = relationship_type

    if rt in COMMON_RELATIONSHIPS:
        if rt in _SAME_TYPE_COMMON and src != tgt:
            return f"{rt!r} requires source and target to be the same object type, but got {src!r} and {tgt!r}"
        return None

    if rt in KNOWN_RELATIONSHIP_TYPES:
        # Only judge combinations between two known core object types.
        if src in CORE_TYPES and tgt in CORE_TYPES:
            allowed = ALLOWED_RELATIONSHIPS.get((src, rt))
            if allowed is None:
                return f"{src!r} is not a defined source for the {rt!r} relationship"
            if tgt not in allowed:
                return f"{src} --{rt}--> {tgt} is not a permitted relationship; valid targets are: {', '.join(sorted(allowed))}"
        return None

    # User-defined relationship type: allowed between any SDO/SCO.
    return None


# ---------------------------------------------------------------------------
# Common base for SROs (SROs are versioned and share the SDO common properties)
# ---------------------------------------------------------------------------


class STIXRelationshipObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Required common properties
    id: str = Field(..., pattern=rf"^[a-z0-9-]+--{_UUID}$")
    type: str
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
    extensions: dict | None = None

    @model_validator(mode="after")
    def _id_prefix_matches_type(self) -> STIXRelationshipObject:
        expected = self.type
        prefix = self.id.split("--", 1)[0]
        if prefix != expected:
            msg = f"id prefix {prefix!r} does not match type {expected!r}"
            raise ValueError(msg)
        return self


class Relationship(STIXRelationshipObject):
    type: Literal["relationship"] = "relationship"
    relationship_type: Annotated[str, Field(pattern=_RELATIONSHIP_TYPE_RE)]
    source_ref: AnyRef
    target_ref: AnyRef
    description: str | None = None
    start_time: Timestamp | None = None
    stop_time: Timestamp | None = None

    @model_validator(mode="after")
    def _validate_relationship(self) -> Relationship:
        if self.start_time is not None and self.stop_time is not None and self.stop_time <= self.start_time:
            msg = "stop_time MUST be later than start_time"
            raise ValueError(msg)

        error = check_relationship_endpoints(self.source_ref, self.target_ref, self.relationship_type)
        if error is not None:
            raise ValueError(error)
        return self


class Sighting(STIXRelationshipObject):
    type: Literal["sighting"] = "sighting"
    sighting_of_ref: AnyRef  # MUST reference an SDO (validated below)
    description: str | None = None
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    count: Annotated[int, Field(ge=0, le=999_999_999)] | None = None
    observed_data_refs: Annotated[list[ObservedDataRef], Field(min_length=1)] | None = None
    where_sighted_refs: Annotated[list[IdentityOrLocationRef], Field(min_length=1)] | None = None
    summary: bool | None = None

    @model_validator(mode="after")
    def _validate_sighting(self) -> Sighting:
        # sighting_of_ref MUST reference only an SDO.
        sighted = _prefix(self.sighting_of_ref)
        if sighted not in SDO_TYPES:
            msg = f"sighting_of_ref must reference an SDO, not a {sighted!r} object"
            raise ValueError(msg)

        if self.first_seen is not None and self.last_seen is not None and self.last_seen < self.first_seen:
            msg = "last_seen MUST be greater than or equal to first_seen"
            raise ValueError(msg)
        return self
