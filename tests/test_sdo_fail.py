from stix2utils.validator import STIX2Validator


def test_none_value() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(None)

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert (
        validation_result.errors[0].description
        == "(root): Input should be a valid dictionary or object to extract fields from [model_attributes_type]"
    )


def test_empty_dict() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity({})

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "(root): Unable to extract tag using discriminator 'type' [union_tag_not_found]"


def test_missing_required_field_type() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "spec_version": "2.1",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Malicious IP Address",
            "description": "This IP address has been observed in C2 communications.",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value = '198.51.100.23']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2024-01-15T08:00:00.000Z",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "(root): Unable to extract tag using discriminator 'type' [union_tag_not_found]"


def test_missing_required_field_id() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "indicator",
            "spec_version": "2.1",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Malicious IP Address",
            "description": "This IP address has been observed in C2 communications.",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value = '198.51.100.23']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2024-01-15T08:00:00.000Z",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "indicator.id: Field required [missing]"


def test_missing_required_field_id_pattern() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "indicator",
            "spec_version": "2.1",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Malicious IP Address",
            "description": "This IP address has been observed in C2 communications.",
            "indicator_types": ["malicious-activity"],
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2024-01-15T08:00:00.000Z",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 2
    assert validation_result.errors[0].description == "indicator.id: Field required [missing]"
    assert validation_result.errors[1].description == "indicator.pattern: Field required [missing]"


def test_invalid_created_by_ref() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "type": "indicator",
            "spec_version": "2.1",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Malicious IP Address",
            "description": "This IP address has been observed in C2 communications.",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value = '198.51.100.23']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "created_by_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd41",
            "valid_from": "2024-01-15T08:00:00.000Z",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert (
        validation_result.errors[0].description
        == "indicator.created_by_ref: String should match pattern '^identity--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' [string_pattern_mismatch]"
    )


def test_id_mismatch() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd41",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Block Malicious IP",
            "description": "Add the malicious IP to the firewall blocklist.",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert (
        validation_result.errors[0].description
        == "course-of-action: Value error, id prefix 'indicator' does not match type 'course-of-action' [value_error]"
    )


def test_bad_created_timestamp() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "created": "2024-01-15T08:00:00.000",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Spear Phishing",
            "description": "A targeted phishing attack against specific individuals.",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert (
        validation_result.errors[0].description
        == "attack-pattern.created: String should match pattern '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z$' [string_pattern_mismatch]"
    )


def test_first_seen_timestamp() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd4d",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "first_seen": "202-01-15T08:00:00.000Z",
            "name": "Nightfall Group",
            "threat_actor_types": ["crime-syndicate"],
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1


def test_bad_confidence() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Spear Phishing",
            "confidence": -1,
            "description": "A targeted phishing attack against specific individuals.",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert (
        validation_result.errors[0].description
        == "attack-pattern.confidence: Input should be greater than or equal to 0 [greater_than_equal]"
    )


def test_bad_killchain() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Spear Phishing",
            "kill_chain_phases": [{"woops": "foo", "phase_name": "pre-attack"}],
            "description": "A targeted phishing attack against specific individuals.",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 2
    assert validation_result.errors[0].description == "attack-pattern.kill_chain_phases.0.kill_chain_name: Field required [missing]"
    assert (
        validation_result.errors[1].description
        == "attack-pattern.kill_chain_phases.0.woops: Extra inputs are not permitted [extra_forbidden]"
    )


def test_empty_listy() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Spear Phishing",
            "kill_chain_phases": [],
            "description": "A targeted phishing attack against specific individuals.",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert (
        validation_result.errors[0].description
        == "attack-pattern.kill_chain_phases: List should have at least 1 item after validation, not 0 [too_short]"
    )
