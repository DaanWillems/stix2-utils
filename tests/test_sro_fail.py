from stix2utils.validator import STIX2Validator


def test_relationship_missing_required_field_id() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "relationship.id: Field required [missing]"


def test_relationship_missing_relationship_type() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship.relationship_type: Field required [missing]"
    )


def test_relationship_missing_source_ref() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "indicates",
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship.source_ref: Field required [missing]"
    )


def test_relationship_missing_target_ref() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship.target_ref: Field required [missing]"
    )


def test_relationship_disallowed_combination() -> None:
    # 'indicates' does not permit an identity target.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "target_ref": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship: Value error, indicator --indicates--> identity is not a permitted "
        "relationship; valid targets are: attack-pattern, campaign, infrastructure, "
        "intrusion-set, malware, threat-actor, tool [value_error]"
    )


def test_relationship_undefined_source_for_type() -> None:
    # 'note' is not a defined source for 'uses'.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship: Value error, 'note' is not a defined source for the 'uses' "
        "relationship [value_error]"
    )


def test_relationship_derived_from_type_mismatch() -> None:
    # derived-from requires identical source and target types.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "derived-from",
            "source_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "target_ref": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship: Value error, 'derived-from' requires source and target to be the "
        "same object type, but got 'malware' and 'tool' [value_error]"
    )


def test_relationship_forbidden_target_endpoint() -> None:
    # target_ref must be an SDO or SCO, never a marking-definition (SMO).
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "target_ref": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship: Value error, target_ref must reference an SDO or SCO, not a "
        "'marking-definition' object [value_error]"
    )


def test_relationship_forbidden_source_endpoint() -> None:
    # source_ref must not point to another SRO.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship: Value error, source_ref must reference an SDO or SCO, not a "
        "'relationship' object [value_error]"
    )


def test_relationship_stop_time_before_start_time() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "start_time": "2024-02-01T00:00:00.000Z",
            "stop_time": "2024-01-01T00:00:00.000Z",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship: Value error, stop_time MUST be later than start_time [value_error]"
    )


def test_relationship_bad_relationship_type_format() -> None:
    # Uppercase / underscore are not allowed in relationship_type.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "Indicates_Malware",
            "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "relationship.relationship_type: String should match pattern "
        "'^[a-z0-9]+(-[a-z0-9]+)*$' [string_pattern_mismatch]"
    )


def test_sighting_missing_sighting_of_ref() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "sighting.sighting_of_ref: Field required [missing]"
    )


def test_sighting_of_ref_must_be_sdo() -> None:
    # sighting_of_ref must reference an SDO, not an SCO.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "sighting_of_ref": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "sighting: Value error, sighting_of_ref must reference an SDO, not a "
        "'ipv4-addr' object [value_error]"
    )


def test_sighting_bad_observed_data_ref_type() -> None:
    # observed_data_refs must reference only observed-data objects.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "observed_data_refs": [
                "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
            ],
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "sighting.observed_data_refs.0: String should match pattern "
        "'^observed-data--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "
        "[string_pattern_mismatch]"
    )


def test_sighting_bad_where_sighted_ref_type() -> None:
    # where_sighted_refs must reference only identity or location objects.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "where_sighted_refs": [
                "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
            ],
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "sighting.where_sighted_refs.0: String should match pattern "
        "'^(?:identity|location)--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
        "[0-9a-f]{12}$' [string_pattern_mismatch]"
    )


def test_sighting_count_out_of_range() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "count": 1_000_000_000,
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "sighting.count: Input should be less than or equal to 999999999 [less_than_equal]"
    )


def test_sighting_last_seen_before_first_seen() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "first_seen": "2024-01-12T19:00:00.000Z",
            "last_seen": "2024-01-10T19:00:00.000Z",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "sighting: Value error, last_seen MUST be greater than or equal to first_seen "
        "[value_error]"
    )
