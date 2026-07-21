from stix2utils.validator import STIX2Validator


def test_missing_required_field_id_artifact() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "artifact",
            "spec_version": "2.1",
            "mime_type": "image/jpeg",
            "payload_bin": "VBORw0KGgoAAAANSUhEUgAAADI=",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "artifact.id: Field required [missing]"


def test_artifact_requires_payload_or_url() -> None:
    # Neither payload_bin nor url provided -> model_validator failure.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "artifact",
            "spec_version": "2.1",
            "id": "artifact--ca17bcf8-9846-5ab4-8662-75c1bf6e63ee",
            "mime_type": "image/jpeg",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "artifact: Value error, exactly one of payload_bin or url MUST be provided [value_error]"
    )


def test_autonomous_system_missing_number() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74",
            "name": "Slime Industries",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == ("autonomous-system.number: Field required [missing]")


def test_directory_missing_path() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "directory",
            "spec_version": "2.1",
            "id": "directory--93c0a9b0-520d-545d-9094-1a08ddf46b05",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "directory.path: Field required [missing]"


def test_domain_name_bad_resolves_to_ref_type() -> None:
    # resolves_to_refs must point to ipv4-addr/ipv6-addr/domain-name, not url.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
            "value": "example.com",
            "resolves_to_refs": ["url--c1477287-23ac-5971-a010-5c287877fa60"],
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "domain-name.resolves_to_refs.0: String should match pattern "
        "'^(?:ipv4-addr|ipv6-addr|domain-name)--"
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' [string_pattern_mismatch]"
    )


def test_email_address_missing_value() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--2d77a846-6264-5d51-b586-e43822ea1ea3",
            "display_name": "John Doe",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "email-addr.value: Field required [missing]"


def test_email_message_missing_is_multipart() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265",
            "subject": "Saying Hello",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == ("email-message.is_multipart: Field required [missing]")


def test_email_message_body_conflicts_with_multipart() -> None:
    # body MUST NOT be set when is_multipart is true -> model_validator failure.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265",
            "is_multipart": True,
            "body": "should not be here",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "email-message: Value error, body MUST NOT be used if is_multipart is true [value_error]"
    )


def test_file_requires_hashes_or_name() -> None:
    # Neither hashes nor name -> model_validator failure.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--e277603e-1060-5ad4-9937-c26c97f1ca68",
            "size": 25536,
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "file: Value error, File object MUST contain at least one of hashes or name [value_error]"
    )


def test_file_negative_size() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--e277603e-1060-5ad4-9937-c26c97f1ca68",
            "name": "foo.dll",
            "size": -1,
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == ("file.size: Input should be greater than or equal to 0 [greater_than_equal]")


def test_ipv4_address_missing_value() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "ipv4-addr.value: Field required [missing]"


def test_ipv6_address_missing_value() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "ipv6-addr.value: Field required [missing]"


def test_mac_address_uppercase_value() -> None:
    # MAC must be lowercase colon-delimited MAC-48.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "mac-addr",
            "spec_version": "2.1",
            "id": "mac-addr--65cfcf98-8a6e-5a1b-8f61-379ac4f92d00",
            "value": "D2:FB:49:24:37:18",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "mac-addr.value: String should match pattern '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' [string_pattern_mismatch]"
    )


def test_mutex_missing_name() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "mutex",
            "spec_version": "2.1",
            "id": "mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "mutex.name: Field required [missing]"


def test_network_traffic_missing_protocols() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--2568d22a-8998-58eb-99ec-3c8ca74f527d",
            "src_ref": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == ("network-traffic.protocols: Field required [missing]")


def test_network_traffic_requires_src_or_dst() -> None:
    # protocols present but neither src_ref nor dst_ref -> model_validator failure.
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--2568d22a-8998-58eb-99ec-3c8ca74f527d",
            "protocols": ["tcp"],
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "network-traffic: Value error, Network Traffic MUST contain at least one of src_ref or dst_ref [value_error]"
    )


def test_process_requires_at_least_one_property() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "process",
            "spec_version": "2.1",
            "id": "process--d2ec5aab-808d-4492-890a-3c1a1e3cb06e",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "process: Value error, Process object MUST contain at least one property (or extension) [value_error]"
    )


def test_software_missing_name() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "software",
            "spec_version": "2.1",
            "id": "software--a1827f6d-ca53-5605-9e93-4316cd22a00a",
            "vendor": "Microsoft",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "software.name: Field required [missing]"


def test_url_missing_value() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "url",
            "spec_version": "2.1",
            "id": "url--c1477287-23ac-5971-a010-5c287877fa60",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == "url.value: Field required [missing]"


def test_user_account_requires_at_least_one_property() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "user-account",
            "spec_version": "2.1",
            "id": "user-account--0d5b424b-93b8-5cd8-ac36-306e1789d63c",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "user-account: Value error, User Account object MUST contain at least one property [value_error]"
    )


def test_windows_registry_key_requires_at_least_one_property() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "windows-registry-key",
            "spec_version": "2.1",
            "id": "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "windows-registry-key: Value error, Windows Registry Key object MUST contain at least one property [value_error]"
    )


def test_x509_certificate_requires_at_least_one_property() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--463d7b2a-8516-5a50-a3d7-6f801465d5de",
        }
    )

    assert not validation_result.success
    assert len(validation_result.errors) == 1
    assert validation_result.errors[0].description == (
        "x509-certificate: Value error, X.509 Certificate object MUST contain at least one specific property [value_error]"
    )
