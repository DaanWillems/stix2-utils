"""Tests for STIX 2.1 open-vocabulary checks (reported as warnings, never errors)."""

import copy

import pytest

from stix2utils import STIX2Validator
from stix2utils.common import HashAlgorithm
from stix2utils.vocabs import HashAlgorithmOv, IndicatorTypeOv, OpenVocabulary

TS = "2024-01-15T08:00:00.000Z"
UUID = "0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"


def _sdo(type_: str, **props) -> dict:
    return {"type": type_, "spec_version": "2.1", "id": f"{type_}--{UUID}", "created": TS, "modified": TS, **props}


def _sco(type_: str, **props) -> dict:
    return {"type": type_, "spec_version": "2.1", "id": f"{type_}--{UUID}", **props}


BASE_OBJECTS = {
    "grouping": _sdo("grouping", context="suspicious-activity", object_refs=[f"indicator--{UUID}"]),
    "identity": _sdo("identity", name="ACME"),
    "indicator": _sdo("indicator", name="i", description="d", pattern="[file:name = 'a']", pattern_type="stix", valid_from=TS),
    "infrastructure": _sdo("infrastructure", name="infra"),
    "intrusion-set": _sdo("intrusion-set", name="set"),
    "location": _sdo("location", region="europe"),
    "malware": _sdo("malware", name="m", is_family=True),
    "malware-analysis": _sdo("malware-analysis", product="sandbox", analysis_sco_refs=[f"file--{UUID}"]),
    "report": _sdo("report", name="r", report_types=["campaign"], published=TS, object_refs=[f"indicator--{UUID}"]),
    "threat-actor": _sdo("threat-actor", name="ta", threat_actor_types=["crime-syndicate"]),
    "tool": _sdo("tool", name="t", tool_types=["remote-access"]),
    "user-account": _sco("user-account", user_id="1001"),
}

# (object type, property, in-vocabulary value, vocabulary name, is_list)
VOCAB_PROPERTIES = [
    ("grouping", "context", "malware-analysis", "grouping-context-ov", False),
    ("identity", "identity_class", "organization", "identity-class-ov", False),
    ("identity", "sectors", "financial-services", "industry-sector-ov", True),
    ("indicator", "indicator_types", "malicious-activity", "indicator-type-ov", True),
    ("indicator", "pattern_type", "yara", "pattern-type-ov", False),
    ("infrastructure", "infrastructure_types", "botnet", "infrastructure-type-ov", True),
    ("intrusion-set", "resource_level", "government", "attack-resource-level-ov", False),
    ("intrusion-set", "primary_motivation", "ideology", "attack-motivation-ov", False),
    ("intrusion-set", "secondary_motivations", "personal-gain", "attack-motivation-ov", True),
    ("location", "region", "western-europe", "region-ov", False),
    ("malware", "malware_types", "ransomware", "malware-type-ov", True),
    ("malware", "architecture_execution_envs", "x86-64", "processor-architecture-ov", True),
    ("malware", "implementation_languages", "c++", "implementation-language-ov", True),
    ("malware", "capabilities", "persists-after-system-reboot", "malware-capabilities-ov", True),
    ("malware-analysis", "result", "malicious", "malware-result-ov", False),
    ("report", "report_types", "threat-report", "report-type-ov", True),
    ("threat-actor", "threat_actor_types", "nation-state", "threat-actor-type-ov", True),
    ("threat-actor", "roles", "agent", "threat-actor-role-ov", True),
    ("threat-actor", "sophistication", "expert", "threat-actor-sophistication-ov", False),
    ("threat-actor", "resource_level", "club", "attack-resource-level-ov", False),
    ("threat-actor", "primary_motivation", "revenge", "attack-motivation-ov", False),
    ("threat-actor", "secondary_motivations", "dominance", "attack-motivation-ov", True),
    ("threat-actor", "personal_motivations", "notoriety", "attack-motivation-ov", True),
    ("tool", "tool_types", "exploitation", "tool-type-ov", True),
    ("user-account", "account_type", "windows-domain", "account-type-ov", False),
]
IDS = [f"{t}.{p}" for t, p, *_ in VOCAB_PROPERTIES]


def _with(type_: str, prop: str, value: str, *, is_list: bool) -> dict:
    obj = copy.deepcopy(BASE_OBJECTS[type_])
    obj[prop] = [value] if is_list else value
    return obj


def _warnings(obj: dict) -> list[str]:
    result = STIX2Validator().validate_entity(obj)
    assert result.is_valid, [e.description for e in result.errors]
    return [w.description for w in result.warnings]


def test_base_objects_have_no_warnings() -> None:
    for obj in BASE_OBJECTS.values():
        assert _warnings(obj) == []


@pytest.mark.parametrize(("type_", "prop", "good", "vocab", "is_list"), VOCAB_PROPERTIES, ids=IDS)
def test_in_vocabulary_value_has_no_warning(type_, prop, good, vocab, is_list) -> None:  # noqa: ARG001
    assert _warnings(_with(type_, prop, good, is_list=is_list)) == []


@pytest.mark.parametrize(("type_", "prop", "good", "vocab", "is_list"), VOCAB_PROPERTIES, ids=IDS)
def test_custom_value_is_valid_with_one_warning(type_, prop, good, vocab, is_list) -> None:  # noqa: ARG001
    assert _warnings(_with(type_, prop, "x-custom-value", is_list=is_list)) == [f"{prop}: 'x-custom-value' is not a value in {vocab}"]


def test_list_warns_once_per_custom_item() -> None:
    obj = _with("malware", "malware_types", "ransomware", is_list=True)
    obj["malware_types"] = ["ransomware", "cryptominer", "trojan", "wiper-ish"]
    assert _warnings(obj) == [
        "malware_types: 'cryptominer' is not a value in malware-type-ov",
        "malware_types: 'wiper-ish' is not a value in malware-type-ov",
    ]


def test_case_mismatch_warns_like_any_unknown_value() -> None:
    obj = _with("indicator", "indicator_types", "Malicious-Activity", is_list=True)
    assert _warnings(obj) == ["indicator_types: 'Malicious-Activity' is not a value in indicator-type-ov"]


def test_multiple_vocab_properties_each_warn() -> None:
    obj = copy.deepcopy(BASE_OBJECTS["threat-actor"])
    obj |= {"threat_actor_types": ["activist", "pirate"], "sophistication": "godlike", "primary_motivation": "boredom"}
    assert _warnings(obj) == [
        "threat_actor_types: 'pirate' is not a value in threat-actor-type-ov",
        "sophistication: 'godlike' is not a value in threat-actor-sophistication-ov",
        "primary_motivation: 'boredom' is not a value in attack-motivation-ov",
    ]


def test_standard_hash_keys_have_no_warning() -> None:
    obj = _sco("file", name="a.exe", hashes={key.value: "ab" for key in HashAlgorithmOv})
    assert _warnings(obj) == []


def test_custom_hash_key_warns() -> None:
    obj = _sco("file", name="a.exe", hashes={"SHA-256": "ab", "SHA-224": "cd"})
    assert _warnings(obj) == ["hashes: key 'SHA-224' is not a value in hash-algorithm-ov"]


def test_custom_hash_key_on_artifact_and_x509() -> None:
    artifact = _sco("artifact", url="https://example.com/a.bin", hashes={"md5": "ab"})
    assert _warnings(artifact) == ["hashes: key 'md5' is not a value in hash-algorithm-ov"]
    cert = _sco("x509-certificate", serial_number="01", hashes={"SHA-1": "ab", "BLAKE3": "cd"})
    assert _warnings(cert) == ["hashes: key 'BLAKE3' is not a value in hash-algorithm-ov"]


def test_nested_extension_reports_full_path() -> None:
    obj = _sco(
        "file",
        name="a.elf",
        extensions={"windows-pebinary-ext": {"pe_type": "elf", "sections": [{"name": ".text", "hashes": {"MD5": "aa", "foo": "bb"}}]}},
    )
    assert _warnings(obj) == [
        "extensions.windows-pebinary-ext.pe_type: 'elf' is not a value in windows-pebinary-type-ov",
        "extensions.windows-pebinary-ext.sections.0.hashes: key 'foo' is not a value in hash-algorithm-ov",
    ]


def test_nested_extension_in_vocabulary_has_no_warning() -> None:
    obj = _sco("file", name="a.dll", extensions={"windows-pebinary-ext": {"pe_type": "dll"}})
    assert _warnings(obj) == []


def test_bundle_prefixes_object_warnings() -> None:
    indicator = _with("indicator", "indicator_types", "x-custom", is_list=True)
    bundle = {"type": "bundle", "id": f"bundle--{UUID}", "objects": [BASE_OBJECTS["identity"], indicator]}
    assert _warnings(bundle) == [f"objects.1 (indicator--{UUID}): indicator_types: 'x-custom' is not a value in indicator-type-ov"]


def test_vocabulary_helpers() -> None:
    assert IndicatorTypeOv.__vocab_name__ == "indicator-type-ov"
    assert IndicatorTypeOv.contains("benign")
    assert not IndicatorTypeOv.contains("Benign")
    assert issubclass(IndicatorTypeOv, OpenVocabulary)
    assert HashAlgorithm is HashAlgorithmOv


# ---------------------------------------------------------------------------
# Regression tests for should() bugs fixed alongside the vocabulary checks
# ---------------------------------------------------------------------------


def test_attack_pattern_without_kill_chain_phases_does_not_crash() -> None:
    assert _warnings(_sdo("attack-pattern", name="Spear Phishing")) == []


def test_indicator_should_returns_warning_list() -> None:
    obj = _sdo("indicator", pattern="[file:name = 'a']", pattern_type="stix", valid_from=TS)
    assert _warnings(obj) == ["name is missing", "description is missing"]


def test_phase_name_space_check_uses_phase_name() -> None:
    ok = _sdo("attack-pattern", name="x", kill_chain_phases=[{"kill_chain_name": "my chain", "phase_name": "recon"}])
    assert _warnings(ok) == ["kill_chain_name should not contain spaces or underscores"]
    bad = _sdo("attack-pattern", name="x", kill_chain_phases=[{"kill_chain_name": "chain", "phase_name": "initial access"}])
    assert _warnings(bad) == ["phase_name should not contain spaces or underscores"]


@pytest.mark.parametrize("type_", ["indicator", "infrastructure", "malware", "tool"])
def test_kill_chain_checks_run_for_all_sdos_with_kill_chain_phases(type_) -> None:
    obj = copy.deepcopy(BASE_OBJECTS[type_])
    obj["kill_chain_phases"] = [{"kill_chain_name": "Chain", "phase_name": "recon"}]
    assert _warnings(obj) == ["kill_chain_name should be lowercase"]
