from stix2utils.sdo_models import AttackPattern
from stix2utils.validator import STIX2Validator

ATTACK_PATTERN = {
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "name": "Spear Phishing",
}


def test_strict_is_default() -> None:
    assert STIX2Validator().strict is True


def test_strict_rejects_custom_property() -> None:
    validation_result = STIX2Validator(strict=True).validate_entity({**ATTACK_PATTERN, "x_custom_score": 7})

    assert not validation_result.is_valid
    assert validation_result.obj is None
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "attack-pattern.x_custom_score: Extra inputs are not permitted [extra_forbidden]"


def test_default_rejects_custom_property() -> None:
    validation_result = STIX2Validator().validate_entity({**ATTACK_PATTERN, "x_custom_score": 7})

    assert not validation_result.is_valid


def test_non_strict_allows_custom_property() -> None:
    validation_result = STIX2Validator(strict=False).validate_entity({**ATTACK_PATTERN, "x_custom_score": 7, "x_acme_tags": ["a"]})

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0
    assert type(validation_result.obj) is AttackPattern
    assert validation_result.obj.model_extra == {"x_custom_score": 7, "x_acme_tags": ["a"]}


def test_non_strict_allows_custom_property_on_nested_object() -> None:
    obj = {**ATTACK_PATTERN, "kill_chain_phases": [{"kill_chain_name": "mitre", "phase_name": "initial-access", "x_note": "n"}]}

    assert not STIX2Validator(strict=True).validate_entity(obj).is_valid

    validation_result = STIX2Validator(strict=False).validate_entity(obj)
    assert validation_result.is_valid
    assert validation_result.obj.kill_chain_phases[0].model_extra == {"x_note": "n"}


def test_non_strict_allows_custom_property_in_bundle() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
        "objects": [{**ATTACK_PATTERN, "x_custom_score": 7}],
    }

    strict_result = STIX2Validator(strict=True).validate_entity(bundle)
    assert not strict_result.is_valid
    assert (
        strict_result.errors[0].description
        == "bundle.objects.0.attack-pattern.x_custom_score: Extra inputs are not permitted [extra_forbidden]"
    )

    validation_result = STIX2Validator(strict=False).validate_entity(bundle)
    assert validation_result.is_valid
    assert validation_result.obj.objects[0].model_extra == {"x_custom_score": 7}


def test_non_strict_still_reports_other_errors() -> None:
    obj = {k: v for k, v in ATTACK_PATTERN.items() if k != "name"}
    validation_result = STIX2Validator(strict=False).validate_entity({**obj, "x_custom_score": 7})

    assert not validation_result.is_valid
    assert validation_result.errors[0].description == "attack-pattern.name: Field required [missing]"
