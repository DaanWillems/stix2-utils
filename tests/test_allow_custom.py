import pytest

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

CUSTOM_WARNING = "custom property is not defined in the STIX 2.1 specification"


def warning_descriptions(validation_result) -> list[str]:
    return [w.description for w in validation_result.warnings]


def test_custom_not_allowed_by_default() -> None:
    assert STIX2Validator().allow_custom is False

    validation_result = STIX2Validator().validate_entity({**ATTACK_PATTERN, "x_custom_score": 7})

    assert not validation_result.is_valid
    assert validation_result.obj is None
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "attack-pattern.x_custom_score: Extra inputs are not permitted [extra_forbidden]"


def test_allow_custom_false_rejects_custom_property() -> None:
    validation_result = STIX2Validator(allow_custom=False).validate_entity({**ATTACK_PATTERN, "x_custom_score": 7})

    assert not validation_result.is_valid


def test_allow_custom_accepts_custom_property_with_warning() -> None:
    validation_result = STIX2Validator(allow_custom=True).validate_entity({**ATTACK_PATTERN, "x_custom_score": 7, "x_acme_tags": ["a"]})

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0
    assert type(validation_result.obj) is AttackPattern
    assert validation_result.obj.model_extra == {"x_custom_score": 7, "x_acme_tags": ["a"]}
    assert warning_descriptions(validation_result) == [
        f"x_custom_score: {CUSTOM_WARNING}",
        f"x_acme_tags: {CUSTOM_WARNING}",
    ]


def test_allow_custom_warns_on_typo() -> None:
    validation_result = STIX2Validator(allow_custom=True).validate_entity({**ATTACK_PATTERN, "descriptin": "oops"})

    assert validation_result.is_valid
    assert validation_result.obj.description is None
    assert warning_descriptions(validation_result) == [f"descriptin: {CUSTOM_WARNING}"]


def test_allow_custom_without_custom_properties_has_no_warnings() -> None:
    validation_result = STIX2Validator(allow_custom=True).validate_entity(ATTACK_PATTERN)

    assert validation_result.is_valid
    assert validation_result.warnings == []


def test_allow_custom_on_nested_object() -> None:
    obj = {**ATTACK_PATTERN, "kill_chain_phases": [{"kill_chain_name": "mitre", "phase_name": "initial-access", "x_note": "n"}]}

    assert not STIX2Validator().validate_entity(obj).is_valid

    validation_result = STIX2Validator(allow_custom=True).validate_entity(obj)
    assert validation_result.is_valid
    assert validation_result.obj.kill_chain_phases[0].model_extra == {"x_note": "n"}
    assert warning_descriptions(validation_result) == [f"kill_chain_phases.0.x_note: {CUSTOM_WARNING}"]


def test_allow_custom_in_bundle() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
        "x_bundle_source": "feed",
        "objects": [{**ATTACK_PATTERN, "x_custom_score": 7}],
    }

    rejected_result = STIX2Validator().validate_entity(bundle)
    assert not rejected_result.is_valid
    assert {e.description for e in rejected_result.errors} == {
        "bundle.x_bundle_source: Extra inputs are not permitted [extra_forbidden]",
        "bundle.objects.0.attack-pattern.x_custom_score: Extra inputs are not permitted [extra_forbidden]",
    }

    validation_result = STIX2Validator(allow_custom=True).validate_entity(bundle)
    assert validation_result.is_valid
    assert validation_result.obj.objects[0].model_extra == {"x_custom_score": 7}
    assert warning_descriptions(validation_result) == [
        f"x_bundle_source: {CUSTOM_WARNING}",
        f"objects.0.x_custom_score: {CUSTOM_WARNING}",
    ]


def test_extension_definition_keys_are_not_custom_property_warnings() -> None:
    file_obj = {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--66156fad-2a7d-5237-bbb4-ba1912887cfe",
        "name": "foo.exe",
        "extensions": {"extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {"extension_type": "property-extension", "rank": 5}},
    }

    validation_result = STIX2Validator(allow_custom=True).validate_entity(file_obj)

    assert validation_result.is_valid
    assert warning_descriptions(validation_result) == []


def test_allow_custom_still_reports_other_errors() -> None:
    obj = {k: v for k, v in ATTACK_PATTERN.items() if k != "name"}
    validation_result = STIX2Validator(allow_custom=True).validate_entity({**obj, "x_custom_score": 7})

    assert not validation_result.is_valid
    assert validation_result.errors[0].description == "attack-pattern.name: Field required [missing]"


FILE_WITH_EXTENSIONS = {
    "type": "file",
    "spec_version": "2.1",
    "id": "file--66156fad-2a7d-5237-bbb4-ba1912887cfe",
    "name": "foo.exe",
    "extensions": {
        "ntfs-ext": {"sid": "1"},
        "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {"extension_type": "property-extension", "rank": 5},
    },
}


@pytest.mark.parametrize("allow_custom", [False, True])
def test_extension_definition_keys_are_accepted_in_both_modes(allow_custom) -> None:
    validation_result = STIX2Validator(allow_custom=allow_custom).validate_entity(FILE_WITH_EXTENSIONS)

    assert validation_result.is_valid, validation_result.errors
    assert warning_descriptions(validation_result) == []


@pytest.mark.parametrize("allow_custom", [False, True])
def test_misspelled_predefined_extension_is_rejected_in_both_modes(allow_custom) -> None:
    obj = {**FILE_WITH_EXTENSIONS, "extensions": {"ntfs_ext": {"sid": "1"}}}

    validation_result = STIX2Validator(allow_custom=allow_custom).validate_entity(obj)

    assert not validation_result.is_valid
    assert "must be an extension-definition id" in validation_result.errors[0].description
