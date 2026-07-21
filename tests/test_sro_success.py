from stix2utils.validator import STIX2Validator


def test_relationship() -> None:
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
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "description": "The indicator detects this malware.",
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_relationship_common_related_to() -> None:
    # related-to is permitted between any two SDOs/SCOs.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "target_ref": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_relationship_derived_from_same_type() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "derived-from",
            "source_ref": "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
            "target_ref": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd40",
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_relationship_user_defined_type() -> None:
    # A relationship type the spec does not define is permitted between any SDO/SCO.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--7aebe2f0-28d6-48a2-9c3e-b0aaa60266ed",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "delivered-by",
            "source_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "target_ref": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_relationship_infrastructure_consists_of_sco() -> None:
    # infrastructure consists-of accepts any SCO type (<All SCOs>).
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--7aebe2f0-28d6-48a2-9c3e-b0aaa60266ef",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "consists-of",
            "source_ref": "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
            "target_ref": "ipv4-addr--b4e29b62-2053-47c4-bab4-bbce39e5ed67",
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_relationship_sco_level_resolves_to() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--2f340a76-edef-443d-a203-bede067c0bb0",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "resolves-to",
            "source_ref": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
            "target_ref": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_relationship_with_time_window() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
            "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "start_time": "2024-01-01T00:00:00.000Z",
            "stop_time": "2024-02-01T00:00:00.000Z",
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_sighting() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_sighting_full() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c76",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "first_seen": "2024-01-10T19:00:00.000Z",
            "last_seen": "2024-01-12T19:00:00.000Z",
            "count": 50,
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "observed_data_refs": ["observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"],
            "where_sighted_refs": ["identity--b67d30ff-02ac-498a-92f9-32f845f448ff"],
            "summary": False,
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0


def test_sighting_where_sighted_location() -> None:
    # where_sighted_refs also accepts Location.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c77",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "sighting_of_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "where_sighted_refs": ["location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64"],
        }
    )

    assert validation_result.success
    assert len(validation_result.errors) == 0
