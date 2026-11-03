"""Tests for STIX 2.1 constraints: timestamps, identifiers, meta objects and property rules."""

from typing import Any

import pytest

from stix2utils.common import timestamp_key
from stix2utils.validator import STIX2ValidationResult, STIX2Validator

UUID = "00000000-0000-4000-8000-000000000000"
UUID2 = "00000000-0000-4000-8000-000000000001"
T = "2024-01-15T08:00:00.000Z"


def validate(obj: dict[str, Any]) -> STIX2ValidationResult:
    return STIX2Validator().validate_entity(obj)


def sdo(type_: str, **props: Any) -> dict[str, Any]:
    return {"type": type_, "id": f"{type_}--{UUID}", "spec_version": "2.1", "created": T, "modified": T, **props}


def sco(type_: str, **props: Any) -> dict[str, Any]:
    return {"type": type_, "id": f"{type_}--{UUID}", **props}


def error_text(result: STIX2ValidationResult) -> str:
    return " | ".join(e.description for e in result.errors)


def warning_text(result: STIX2ValidationResult) -> list[str]:
    return [w.description for w in result.warnings]


# --- Timestamps -------------------------------------------------------------


def test_timestamp_ordering_with_fractional_seconds() -> None:
    assert timestamp_key("2020-01-01T00:00:00Z") < timestamp_key("2020-01-01T00:00:00.5Z")
    assert timestamp_key("2020-01-01T00:00:00.05Z") < timestamp_key("2020-01-01T00:00:00.5Z")
    assert timestamp_key("2020-01-01T00:00:00.5Z") == timestamp_key("2020-01-01T00:00:00.500Z")
    assert timestamp_key("2020-01-01T00:00:00Z") == timestamp_key("2020-01-01T00:00:00.000Z")


def test_campaign_last_seen_with_fractional_seconds() -> None:
    result = validate(sdo("campaign", name="c", first_seen="2020-01-01T00:00:00Z", last_seen="2020-01-01T00:00:00.5Z"))
    assert result.is_valid, error_text(result)


def test_relationship_stop_time_with_fractional_seconds() -> None:
    result = validate(
        sdo(
            "relationship",
            relationship_type="related-to",
            source_ref=f"malware--{UUID}",
            target_ref=f"tool--{UUID}",
            start_time="2020-01-01T00:00:00Z",
            stop_time="2020-01-01T00:00:00.5Z",
        )
    )
    assert result.is_valid, error_text(result)


def test_invalid_calendar_date() -> None:
    result = validate({**sdo("campaign", name="c"), "created": "2020-13-45T99:99:99Z"})
    assert not result.is_valid
    assert "is not a valid date and time" in error_text(result)


def test_modified_before_created() -> None:
    result = validate({**sdo("campaign", name="c"), "created": "2021-01-01T00:00:00Z", "modified": "2020-01-01T00:00:00Z"})
    assert "modified MUST be later than or equal to created" in error_text(result)


@pytest.mark.parametrize(
    ("type_", "props"),
    [
        ("indicator", {"pattern": "x", "pattern_type": "stix", "valid_from": "yesterday"}),
        ("report", {"name": "r", "published": "yesterday", "object_refs": [f"malware--{UUID}"]}),
        ("malware-analysis", {"product": "p", "result": "malicious", "submitted": "yesterday"}),
    ],
)
def test_timestamp_properties_reject_free_text(type_: str, props: dict[str, Any]) -> None:
    assert not validate(sdo(type_, **props)).is_valid


def test_indicator_valid_until_equal_to_valid_from() -> None:
    result = validate(sdo("indicator", pattern="x", pattern_type="stix", valid_from=T, valid_until=T))
    assert "valid_until MUST be greater than valid_from" in error_text(result)


def test_network_traffic_end_before_start() -> None:
    result = validate(
        sco("network-traffic", protocols=["tcp"], src_ref=f"ipv4-addr--{UUID}", start="2020-01-02T00:00:00Z", end="2020-01-01T00:00:00Z")
    )
    assert "end MUST be later than or equal to start" in error_text(result)


# --- Identifiers ------------------------------------------------------------


def test_id_with_double_hyphen_in_type() -> None:
    assert not validate(sdo("malware", is_family=False, id=f"malware--evil--{UUID}")).is_valid


def test_reference_with_double_hyphen_in_type() -> None:
    assert not validate(sdo("note", content="c", object_refs=[f"malware--evil--{UUID}"])).is_valid


# --- Optional properties and meta objects -------------------------------------


@pytest.mark.parametrize(
    ("type_", "props"),
    [
        ("report", {"name": "r", "published": T, "object_refs": [f"malware--{UUID}"]}),
        ("tool", {"name": "t"}),
        ("threat-actor", {"name": "t"}),
    ],
)
def test_optional_type_lists(type_: str, props: dict[str, Any]) -> None:
    result = validate(sdo(type_, **props))
    assert result.is_valid, error_text(result)


def test_extension_definition() -> None:
    result = validate(
        sdo(
            "extension-definition",
            created_by_ref=f"identity--{UUID}",
            name="ext",
            schema="https://example.com/schema.json",
            version="1.0.0",
            extension_types=["property-extension"],
        )
    )
    assert result.is_valid, error_text(result)


def test_extension_definition_unknown_extension_type() -> None:
    result = validate(
        sdo(
            "extension-definition",
            created_by_ref=f"identity--{UUID}",
            name="ext",
            schema="s",
            version="1",
            extension_types=["bogus"],
        )
    )
    assert not result.is_valid


def test_language_content() -> None:
    result = validate(sdo("language-content", object_ref=f"campaign--{UUID}", contents={"de": {"name": "Bilbo"}}))
    assert result.is_valid, error_text(result)


def test_bundle_with_language_content() -> None:
    lc = sdo("language-content", object_ref=f"campaign--{UUID}", contents={"de": {"name": "Bilbo"}})
    result = validate({"type": "bundle", "id": f"bundle--{UUID}", "objects": [lc]})
    assert result.is_valid, error_text(result)


# --- Property constraints -----------------------------------------------------


@pytest.mark.parametrize(
    ("obj", "message"),
    [
        (sdo("location"), "at least one of region, country, or latitude and longitude"),
        (sdo("location", latitude=1.0), "latitude and longitude MUST both be present"),
        (sdo("malware-analysis", product="p"), "at least one of result or analysis_sco_refs"),
        (sdo("malware", is_family=True), "name MUST be present when is_family is true"),
        (sdo("observed-data", first_observed=T, last_observed=T, number_observed=1), "exactly one of object_refs or objects"),
        (
            sdo("observed-data", first_observed=T, last_observed=T, number_observed=0, object_refs=[f"file--{UUID}"]),
            "greater than or equal to 1",
        ),
        (sdo("campaign", name="c", external_references=[{"source_name": "x"}]), "at least one of description, url or external_id"),
        (
            sdo("campaign", name="c", granular_markings=[{"selectors": ["name"]}]),
            "exactly one of lang or marking_ref",
        ),
        (sdo("campaign", name="c", extensions={"my-ext": {}}), "must be an extension-definition id"),
        (sco("file", name="f", extensions={"ntfs_ext": {"sid": "1"}}), "must be an extension-definition id"),
        (sco("file", name="f", hashes={"a b": "00"}), "hash key 'a b'"),
        (sco("ipv4-addr", value="999.1.1.1"), "ipv4-addr.value"),
        (sco("ipv6-addr", value="not-an-ip"), "ipv6-addr.value"),
    ],
    ids=[
        "location-without-region-country-or-coordinates",
        "location-latitude-without-longitude",
        "malware-analysis-without-result-or-sco-refs",
        "malware-family-without-name",
        "observed-data-without-object-refs-or-objects",
        "observed-data-number-observed-zero",
        "external-reference-with-only-source-name",
        "granular-marking-without-lang-or-marking-ref",
        "sdo-extension-key-format",
        "file-extension-key-format",
        "hash-key-format",
        "ipv4-addr-invalid",
        "ipv6-addr-invalid",
    ],
)
def test_constraint_violations(obj: dict[str, Any], message: str) -> None:
    result = validate(obj)
    assert not result.is_valid
    assert message in error_text(result)


def test_valid_location_and_extensions() -> None:
    assert validate(sdo("location", country="NL")).is_valid
    assert validate(sdo("location", latitude=1.0, longitude=2.0, precision=10.0)).is_valid
    assert validate(
        sdo("campaign", name="c", extensions={f"extension-definition--{UUID}": {"extension_type": "property-extension"}})
    ).is_valid
    assert validate(sco("file", name="f", extensions={"ntfs-ext": {"sid": "1"}, f"extension-definition--{UUID2}": {}})).is_valid
    assert validate(sco("ipv4-addr", value="198.51.100.0/24")).is_valid
    assert validate(sco("ipv6-addr", value="2001:db8::/32")).is_valid


def test_valid_external_reference_and_granular_marking() -> None:
    result = validate(
        sdo(
            "campaign",
            name="c",
            external_references=[{"source_name": "capec", "external_id": "CAPEC-163"}],
            granular_markings=[{"marking_ref": f"marking-definition--{UUID}", "selectors": ["name"]}],
        )
    )
    assert result.is_valid, error_text(result)
