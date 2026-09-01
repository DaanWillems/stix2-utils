from stix2utils.sdo_models import Indicator
from stix2utils.validator import STIX2Validator


def test_indicator() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Malicious IP Address",
            "description": "This IP address has been observed in C2 communications.",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value = '198.51.100.23']",
            "pattern_type": "stix",
            "confidence": 21,
            "pattern_version": "2.1",
            "valid_from": "2024-01-15T08:00:00.000Z",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0

    assert type(validation_result.obj) is Indicator


def test_attack_pattern() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Spear Phishing",
            "kill_chain_phases": [{"kill_chain_name": "foo", "phase_name": "pre-attack"}],
            "description": "A targeted phishing attack against specific individuals.",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_campaign() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "campaign",
            "spec_version": "2.1",
            "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd40",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Operation Nightfall",
            "description": "A sustained campaign targeting financial institutions.",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_course_of_action() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd41",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Block Malicious IP",
            "description": "Add the malicious IP to the firewall blocklist.",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_grouping() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "grouping",
            "spec_version": "2.1",
            "id": "grouping--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd42",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Related Threat Objects",
            "context": "suspicious-activity",
            "object_refs": [
                "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "malware--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd50",
            ],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_identity() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd43",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "ACME Corporation"
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_infrastructure() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": "infrastructure--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd44",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "C2 Server Cluster",
            "infrastructure_types": ["command-and-control"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_intrusion_set() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": "intrusion-set--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd45",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "APT-Example",
            "description": "A persistent adversary group tracked across campaigns.",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_location() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "location",
            "spec_version": "2.1",
            "id": "location--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd46",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Netherlands",
            "country": "NL",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_malware() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": "malware--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd50",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "ExampleTrojan",
            "malware_types": ["trojan"],
            "is_family": False,
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_malware_analysis() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "malware-analysis",
            "spec_version": "2.1",
            "id": "malware-analysis--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd47",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "product": "example-sandbox",
            "result": "malicious",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_note() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "note",
            "spec_version": "2.1",
            "id": "note--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd48",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "content": "This indicator was confirmed by a second analyst.",
            "object_refs": ["indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_observed_data() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd49",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "first_observed": "2024-01-15T08:00:00.000Z",
            "last_observed": "2024-01-15T08:00:00.000Z",
            "number_observed": 1,
            "object_refs": ["ipv4-addr--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd4a"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_opinion() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "opinion",
            "spec_version": "2.1",
            "id": "opinion--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd4b",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "opinion": "strongly-agree",
            "object_refs": ["indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_report() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd4c",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Threat Report: Operation Nightfall",
            "report_types": ["campaign"],
            "published": "2024-01-15T08:00:00.000Z",
            "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd40"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_threat_actor() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd4d",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Nightfall Group",
            "threat_actor_types": ["crime-syndicate"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_tool() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "tool",
            "spec_version": "2.1",
            "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd4e",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "Remote Access Tool",
            "tool_types": ["remote-access"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_vulnerability() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": "vulnerability--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd4f",
            "created": "2024-01-15T08:00:00.000Z",
            "modified": "2024-01-15T08:00:00.000Z",
            "name": "CVE-2024-0001",
            "description": "An example remote code execution vulnerability.",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_marking() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "created": "2017-01-20T00:00:00.000Z",
            "definition": {"tlp": "amber"},
            "definition_type": "tlp",
            "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "spec_version": "2.1",
            "name": "TLP:AMBER",
            "type": "marking-definition",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0
