from stix2utils.validator import STIX2Validator


def test_bundle_bad_identity() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "bundle",
            "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
            "objects": [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": "identity1--f431f809-377b-45e0-aa1c-6a4751cae5ff",
                    "created": "2026-10-01T09:00:00.000Z",
                    "modified": "2026-10-01T09:00:00.000Z",
                    "name": "Example Threat Intel Team",
                    "sectors": ["technology"],
                    "contact_information": "cti@example.com",
                }
            ],
        }
    )

    assert not validation_result.is_valid
    assert len(validation_result.errors) == 1
    assert (
        validation_result.errors[0].description
        == "bundle.objects.0.identity: Value error, id prefix 'identity1' \
does not match type 'identity' [value_error]"
    )
