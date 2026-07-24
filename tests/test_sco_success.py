from stix2utils.validator import STIX2Validator


def test_artifact() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "artifact",
            "spec_version": "2.1",
            "id": "artifact--ca17bcf8-9846-5ab4-8662-75c1bf6e63ee",
            "mime_type": "image/jpeg",
            "payload_bin": "VBORw0KGgoAAAANSUhEUgAAADI=",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_autonomous_system() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74",
            "number": 15139,
            "name": "Slime Industries",
            "rir": "ARIN",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_directory() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "directory",
            "spec_version": "2.1",
            "id": "directory--93c0a9b0-520d-545d-9094-1a08ddf46b05",
            "path": "C:\\Windows\\System32",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_domain_name() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
            "value": "example.com",
            "resolves_to_refs": ["ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_email_address() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--2d77a846-6264-5d51-b586-e43822ea1ea3",
            "value": "john@example.com",
            "display_name": "John Doe",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_email_message() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265",
            "is_multipart": False,
            "date": "1997-11-21T15:55:06.000Z",
            "from_ref": "email-addr--89f52ea8-d6ef-51e9-8fce-6a29236436ed",
            "to_refs": ["email-addr--e4ee5301-b52d-59cd-a8fa-8036738c7194"],
            "subject": "Saying Hello",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_file() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--e277603e-1060-5ad4-9937-c26c97f1ca68",
            "hashes": {"SHA-256": "fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db"},
            "size": 25536,
            "name": "foo.dll",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_ipv4_address() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
            "value": "198.51.100.3",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_ipv6_address() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1",
            "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_mac_address() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "mac-addr",
            "spec_version": "2.1",
            "id": "mac-addr--65cfcf98-8a6e-5a1b-8f61-379ac4f92d00",
            "value": "d2:fb:49:24:37:18",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_mutex() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "mutex",
            "spec_version": "2.1",
            "id": "mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300",
            "name": "__CLEANSWEEP__",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_network_traffic() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--2568d22a-8998-58eb-99ec-3c8ca74f527d",
            "src_ref": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
            "dst_ref": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
            "protocols": ["tcp"],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_process() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "process",
            "spec_version": "2.1",
            "id": "process--d2ec5aab-808d-4492-890a-3c1a1e3cb06e",
            "pid": 1221,
            "created_time": "2016-01-20T14:11:25.55Z",
            "command_line": "./gedit-bin --new-window",
            "image_ref": "file--e04f22d1-be2c-59de-add8-10f61d15fe20",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_software() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "software",
            "spec_version": "2.1",
            "id": "software--a1827f6d-ca53-5605-9e93-4316cd22a00a",
            "name": "Word",
            "cpe": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
            "version": "2002",
            "vendor": "Microsoft",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_url() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "url",
            "spec_version": "2.1",
            "id": "url--c1477287-23ac-5971-a010-5c287877fa60",
            "value": "https://example.com/research/index.html",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_user_account() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "user-account",
            "spec_version": "2.1",
            "id": "user-account--0d5b424b-93b8-5cd8-ac36-306e1789d63c",
            "user_id": "1001",
            "account_login": "jdoe",
            "account_type": "unix",
            "display_name": "John Doe",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_windows_registry_key() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "windows-registry-key",
            "spec_version": "2.1",
            "id": "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016",
            "key": "HKEY_LOCAL_MACHINE\\System\\Bar\\Foo",
            "values": [
                {
                    "name": "Foo",
                    "data": "qwerty",
                    "data_type": "REG_SZ",
                }
            ],
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0


def test_x509_certificate() -> None:
    validator = STIX2Validator()
    validation_result = validator.validate_entity(
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--463d7b2a-8516-5a50-a3d7-6f801465d5de",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49",
        }
    )

    assert validation_result.is_valid
    assert len(validation_result.errors) == 0
