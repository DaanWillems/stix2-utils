"""STIX 2.1 open vocabularies (STIX 2.1 specification, section 10).

Values of properties backed by an open vocabulary SHOULD come from the
vocabulary, but producers MAY use custom values. Values outside the vocabulary
are therefore reported as warnings, never as validation errors.

The values below are copied verbatim from the specification.
"""

import enum
from dataclasses import dataclass
from typing import Annotated, Any, ClassVar, get_args, get_origin

from pydantic import BaseModel
from pydantic.fields import FieldInfo


class OpenVocabulary(enum.StrEnum):
    """Base class for all STIX 2.1 open vocabularies.

    ``__vocab_name__`` holds the name used in the specification (e.g. ``indicator-type-ov``).
    """

    __vocab_name__: ClassVar[str]

    @classmethod
    def contains(cls, value: str) -> bool:
        """Return True when ``value`` is one of the vocabulary values (case-sensitive)."""
        return value in cls._value2member_map_


class AccountTypeOv(OpenVocabulary):
    """STIX 2.1 ``account-type-ov``."""

    __vocab_name__ = "account-type-ov"

    FACEBOOK = "facebook"
    LDAP = "ldap"
    NIS = "nis"
    OPENID = "openid"
    RADIUS = "radius"
    SKYPE = "skype"
    TACACS = "tacacs"
    TWITTER = "twitter"
    UNIX = "unix"
    WINDOWS_LOCAL = "windows-local"
    WINDOWS_DOMAIN = "windows-domain"


class AttackMotivationOv(OpenVocabulary):
    """STIX 2.1 ``attack-motivation-ov``."""

    __vocab_name__ = "attack-motivation-ov"

    ACCIDENTAL = "accidental"
    COERCION = "coercion"
    DOMINANCE = "dominance"
    IDEOLOGY = "ideology"
    NOTORIETY = "notoriety"
    ORGANIZATIONAL_GAIN = "organizational-gain"
    PERSONAL_GAIN = "personal-gain"
    PERSONAL_SATISFACTION = "personal-satisfaction"
    REVENGE = "revenge"
    UNPREDICTABLE = "unpredictable"


class AttackResourceLevelOv(OpenVocabulary):
    """STIX 2.1 ``attack-resource-level-ov``."""

    __vocab_name__ = "attack-resource-level-ov"

    INDIVIDUAL = "individual"
    CLUB = "club"
    CONTEST = "contest"
    TEAM = "team"
    ORGANIZATION = "organization"
    GOVERNMENT = "government"


class GroupingContextOv(OpenVocabulary):
    """STIX 2.1 ``grouping-context-ov``."""

    __vocab_name__ = "grouping-context-ov"

    SUSPICIOUS_ACTIVITY = "suspicious-activity"
    MALWARE_ANALYSIS = "malware-analysis"
    UNSPECIFIED = "unspecified"


class HashAlgorithmOv(OpenVocabulary):
    """STIX 2.1 ``hash-algorithm-ov``."""

    __vocab_name__ = "hash-algorithm-ov"

    MD5 = "MD5"
    SHA_1 = "SHA-1"
    SHA_256 = "SHA-256"
    SHA_512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"
    SSDEEP = "SSDEEP"
    TLSH = "TLSH"


class IdentityClassOv(OpenVocabulary):
    """STIX 2.1 ``identity-class-ov``."""

    __vocab_name__ = "identity-class-ov"

    INDIVIDUAL = "individual"
    GROUP = "group"
    SYSTEM = "system"
    ORGANIZATION = "organization"
    CLASS = "class"
    UNKNOWN = "unknown"


class ImplementationLanguageOv(OpenVocabulary):
    """STIX 2.1 ``implementation-language-ov``."""

    __vocab_name__ = "implementation-language-ov"

    APPLESCRIPT = "applescript"
    BASH = "bash"
    C = "c"
    CPP = "c++"
    CSHARP = "c#"
    GO = "go"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    LUA = "lua"
    OBJECTIVE_C = "objective-c"
    PERL = "perl"
    PHP = "php"
    POWERSHELL = "powershell"
    PYTHON = "python"
    RUBY = "ruby"
    SCALA = "scala"
    SWIFT = "swift"
    TYPESCRIPT = "typescript"
    VISUAL_BASIC = "visual-basic"
    X86_32 = "x86-32"
    X86_64 = "x86-64"


class IndicatorTypeOv(OpenVocabulary):
    """STIX 2.1 ``indicator-type-ov``."""

    __vocab_name__ = "indicator-type-ov"

    ANOMALOUS_ACTIVITY = "anomalous-activity"
    ANONYMIZATION = "anonymization"
    BENIGN = "benign"
    COMPROMISED = "compromised"
    MALICIOUS_ACTIVITY = "malicious-activity"
    ATTRIBUTION = "attribution"
    UNKNOWN = "unknown"


class IndustrySectorOv(OpenVocabulary):
    """STIX 2.1 ``industry-sector-ov``."""

    __vocab_name__ = "industry-sector-ov"

    AGRICULTURE = "agriculture"
    AEROSPACE = "aerospace"
    AUTOMOTIVE = "automotive"
    CHEMICAL = "chemical"
    COMMERCIAL = "commercial"
    COMMUNICATIONS = "communications"
    CONSTRUCTION = "construction"
    DEFENSE = "defense"
    EDUCATION = "education"
    ENERGY = "energy"
    ENTERTAINMENT = "entertainment"
    FINANCIAL_SERVICES = "financial-services"
    GOVERNMENT = "government"
    EMERGENCY_SERVICES = "emergency-services"
    GOVERNMENT_NATIONAL = "government-national"
    GOVERNMENT_REGIONAL = "government-regional"
    GOVERNMENT_LOCAL = "government-local"
    GOVERNMENT_PUBLIC_SERVICES = "government-public-services"
    HEALTHCARE = "healthcare"
    HOSPITALITY_LEISURE = "hospitality-leisure"
    INFRASTRUCTURE = "infrastructure"
    DAMS = "dams"
    NUCLEAR = "nuclear"
    WATER = "water"
    INSURANCE = "insurance"
    MANUFACTURING = "manufacturing"
    MINING = "mining"
    NON_PROFIT = "non-profit"
    PHARMACEUTICALS = "pharmaceuticals"
    RETAIL = "retail"
    TECHNOLOGY = "technology"
    TELECOMMUNICATIONS = "telecommunications"
    TRANSPORTATION = "transportation"
    UTILITIES = "utilities"


class InfrastructureTypeOv(OpenVocabulary):
    """STIX 2.1 ``infrastructure-type-ov``."""

    __vocab_name__ = "infrastructure-type-ov"

    AMPLIFICATION = "amplification"
    ANONYMIZATION = "anonymization"
    BOTNET = "botnet"
    COMMAND_AND_CONTROL = "command-and-control"
    CONTROL_SYSTEM = "control-system"
    EXFILTRATION = "exfiltration"
    FIREWALL = "firewall"
    HOSTING_MALWARE = "hosting-malware"
    HOSTING_TARGET_LISTS = "hosting-target-lists"
    PHISHING = "phishing"
    RECONNAISSANCE = "reconnaissance"
    ROUTERS_SWITCHES = "routers-switches"
    STAGING = "staging"
    WORKSTATION = "workstation"
    UNKNOWN = "unknown"


class MalwareResultOv(OpenVocabulary):
    """STIX 2.1 ``malware-result-ov``."""

    __vocab_name__ = "malware-result-ov"

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class MalwareCapabilitiesOv(OpenVocabulary):
    """STIX 2.1 ``malware-capabilities-ov``."""

    __vocab_name__ = "malware-capabilities-ov"

    ACCESSES_REMOTE_MACHINES = "accesses-remote-machines"
    ANTI_DEBUGGING = "anti-debugging"
    ANTI_DISASSEMBLY = "anti-disassembly"
    ANTI_EMULATION = "anti-emulation"
    ANTI_MEMORY_FORENSICS = "anti-memory-forensics"
    ANTI_SANDBOX = "anti-sandbox"
    ANTI_VM = "anti-vm"
    CAPTURES_INPUT_PERIPHERALS = "captures-input-peripherals"
    CAPTURES_OUTPUT_PERIPHERALS = "captures-output-peripherals"
    CAPTURES_SYSTEM_STATE_DATA = "captures-system-state-data"
    CLEANS_TRACES_OF_INFECTION = "cleans-traces-of-infection"
    COMMITS_FRAUD = "commits-fraud"
    COMMUNICATES_WITH_C2 = "communicates-with-c2"
    COMPROMISES_DATA_AVAILABILITY = "compromises-data-availability"
    COMPROMISES_DATA_INTEGRITY = "compromises-data-integrity"
    COMPROMISES_SYSTEM_AVAILABILITY = "compromises-system-availability"
    CONTROLS_LOCAL_MACHINE = "controls-local-machine"
    DEGRADES_SECURITY_SOFTWARE = "degrades-security-software"
    DEGRADES_SYSTEM_UPDATES = "degrades-system-updates"
    DETERMINES_C2_SERVER = "determines-c2-server"
    EMAILS_SPAM = "emails-spam"
    ESCALATES_PRIVILEGES = "escalates-privileges"
    EVADES_AV = "evades-av"
    EXFILTRATES_DATA = "exfiltrates-data"
    FINGERPRINTS_HOST = "fingerprints-host"
    HIDES_ARTIFACTS = "hides-artifacts"
    HIDES_EXECUTING_CODE = "hides-executing-code"
    INFECTS_FILES = "infects-files"
    INFECTS_REMOTE_MACHINES = "infects-remote-machines"
    INSTALLS_OTHER_COMPONENTS = "installs-other-components"
    PERSISTS_AFTER_SYSTEM_REBOOT = "persists-after-system-reboot"
    PREVENTS_ARTIFACT_ACCESS = "prevents-artifact-access"
    PREVENTS_ARTIFACT_DELETION = "prevents-artifact-deletion"
    PROBES_NETWORK_ENVIRONMENT = "probes-network-environment"
    SELF_MODIFIES = "self-modifies"
    STEALS_AUTHENTICATION_CREDENTIALS = "steals-authentication-credentials"
    VIOLATES_SYSTEM_OPERATIONAL_INTEGRITY = "violates-system-operational-integrity"


class MalwareTypeOv(OpenVocabulary):
    """STIX 2.1 ``malware-type-ov``."""

    __vocab_name__ = "malware-type-ov"

    ADWARE = "adware"
    BACKDOOR = "backdoor"
    BOT = "bot"
    BOOTKIT = "bootkit"
    DDOS = "ddos"
    DOWNLOADER = "downloader"
    DROPPER = "dropper"
    EXPLOIT_KIT = "exploit-kit"
    KEYLOGGER = "keylogger"
    RANSOMWARE = "ransomware"
    REMOTE_ACCESS_TROJAN = "remote-access-trojan"
    RESOURCE_EXPLOITATION = "resource-exploitation"
    ROGUE_SECURITY_SOFTWARE = "rogue-security-software"
    ROOTKIT = "rootkit"
    SCREEN_CAPTURE = "screen-capture"
    SPYWARE = "spyware"
    TROJAN = "trojan"
    UNKNOWN = "unknown"
    VIRUS = "virus"
    WEBSHELL = "webshell"
    WIPER = "wiper"
    WORM = "worm"


class PatternTypeOv(OpenVocabulary):
    """STIX 2.1 ``pattern-type-ov``."""

    __vocab_name__ = "pattern-type-ov"

    STIX = "stix"
    PCRE = "pcre"
    SIGMA = "sigma"
    SNORT = "snort"
    SURICATA = "suricata"
    YARA = "yara"


class ProcessorArchitectureOv(OpenVocabulary):
    """STIX 2.1 ``processor-architecture-ov``."""

    __vocab_name__ = "processor-architecture-ov"

    ALPHA = "alpha"
    ARM = "arm"
    IA_64 = "ia-64"
    MIPS = "mips"
    POWERPC = "powerpc"
    SPARC = "sparc"
    X86 = "x86"
    X86_64 = "x86-64"


class RegionOv(OpenVocabulary):
    """STIX 2.1 ``region-ov``."""

    __vocab_name__ = "region-ov"

    AFRICA = "africa"
    EASTERN_AFRICA = "eastern-africa"
    MIDDLE_AFRICA = "middle-africa"
    NORTHERN_AFRICA = "northern-africa"
    SOUTHERN_AFRICA = "southern-africa"
    WESTERN_AFRICA = "western-africa"
    AMERICAS = "americas"
    LATIN_AMERICA_CARIBBEAN = "latin-america-caribbean"
    SOUTH_AMERICA = "south-america"
    CARIBBEAN = "caribbean"
    CENTRAL_AMERICA = "central-america"
    NORTHERN_AMERICA = "northern-america"
    ASIA = "asia"
    CENTRAL_ASIA = "central-asia"
    EASTERN_ASIA = "eastern-asia"
    SOUTHERN_ASIA = "southern-asia"
    SOUTH_EASTERN_ASIA = "south-eastern-asia"
    WESTERN_ASIA = "western-asia"
    EUROPE = "europe"
    EASTERN_EUROPE = "eastern-europe"
    NORTHERN_EUROPE = "northern-europe"
    SOUTHERN_EUROPE = "southern-europe"
    WESTERN_EUROPE = "western-europe"
    OCEANIA = "oceania"
    ANTARCTICA = "antarctica"
    AUSTRALIA_NEW_ZEALAND = "australia-new-zealand"
    MELANESIA = "melanesia"
    MICRONESIA = "micronesia"
    POLYNESIA = "polynesia"


class ReportTypeOv(OpenVocabulary):
    """STIX 2.1 ``report-type-ov``."""

    __vocab_name__ = "report-type-ov"

    ATTACK_PATTERN = "attack-pattern"
    CAMPAIGN = "campaign"
    IDENTITY = "identity"
    INDICATOR = "indicator"
    INTRUSION_SET = "intrusion-set"
    MALWARE = "malware"
    OBSERVED_DATA = "observed-data"
    THREAT_ACTOR = "threat-actor"
    THREAT_REPORT = "threat-report"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"


class ThreatActorTypeOv(OpenVocabulary):
    """STIX 2.1 ``threat-actor-type-ov``."""

    __vocab_name__ = "threat-actor-type-ov"

    ACTIVIST = "activist"
    COMPETITOR = "competitor"
    CRIME_SYNDICATE = "crime-syndicate"
    CRIMINAL = "criminal"
    HACKER = "hacker"
    INSIDER_ACCIDENTAL = "insider-accidental"
    INSIDER_DISGRUNTLED = "insider-disgruntled"
    NATION_STATE = "nation-state"
    SENSATIONALIST = "sensationalist"
    SPY = "spy"
    TERRORIST = "terrorist"
    UNKNOWN = "unknown"


class ThreatActorRoleOv(OpenVocabulary):
    """STIX 2.1 ``threat-actor-role-ov``."""

    __vocab_name__ = "threat-actor-role-ov"

    AGENT = "agent"
    DIRECTOR = "director"
    INDEPENDENT = "independent"
    INFRASTRUCTURE_ARCHITECT = "infrastructure-architect"
    INFRASTRUCTURE_OPERATOR = "infrastructure-operator"
    MALWARE_AUTHOR = "malware-author"
    SPONSOR = "sponsor"


class ThreatActorSophisticationOv(OpenVocabulary):
    """STIX 2.1 ``threat-actor-sophistication-ov``."""

    __vocab_name__ = "threat-actor-sophistication-ov"

    NONE = "none"
    MINIMAL = "minimal"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"
    INNOVATOR = "innovator"
    STRATEGIC = "strategic"


class ToolTypeOv(OpenVocabulary):
    """STIX 2.1 ``tool-type-ov``."""

    __vocab_name__ = "tool-type-ov"

    DENIAL_OF_SERVICE = "denial-of-service"
    EXPLOITATION = "exploitation"
    INFORMATION_GATHERING = "information-gathering"
    NETWORK_CAPTURE = "network-capture"
    CREDENTIAL_EXPLOITATION = "credential-exploitation"
    REMOTE_ACCESS = "remote-access"
    VULNERABILITY_SCANNING = "vulnerability-scanning"
    UNKNOWN = "unknown"


class WindowsPEBinaryTypeOv(OpenVocabulary):
    """STIX 2.1 ``windows-pebinary-type-ov``."""

    __vocab_name__ = "windows-pebinary-type-ov"

    DLL = "dll"
    EXE = "exe"
    SYS = "sys"


@dataclass(frozen=True)
class OpenVocab:
    """``Annotated`` marker: the value(s) of this field SHOULD come from ``vocab``.

    Applies to a string, to each item of a list of strings, or, with ``keys=True``,
    to each key of a dictionary (e.g. ``hashes`` keys come from ``hash-algorithm-ov``).
    The marker is metadata only; custom values remain valid.
    """

    vocab: type[OpenVocabulary]
    keys: bool = False


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------


def _markers_in(annotation: Any) -> list[OpenVocab]:  # noqa: ANN401
    """Collect OpenVocab markers nested anywhere in a type annotation (e.g. inside ``X | None``)."""
    found: list[OpenVocab] = []
    if get_origin(annotation) is Annotated:
        found.extend(m for m in annotation.__metadata__ if isinstance(m, OpenVocab))
    for arg in get_args(annotation):
        found.extend(_markers_in(arg))
    return found


def _find_marker(field: FieldInfo) -> OpenVocab | None:
    for marker in field.metadata:
        if isinstance(marker, OpenVocab):
            return marker
    nested = _markers_in(field.annotation)
    return nested[0] if nested else None


def _check_value(marker: OpenVocab, value: Any, loc: str) -> list[str]:  # noqa: ANN401
    vocab = marker.vocab
    if marker.keys and isinstance(value, dict):
        candidates = list(value.keys())
    elif isinstance(value, list):
        candidates = value
    else:
        candidates = [value]
    return [
        f"{loc}: {'key ' if marker.keys else ''}{item!r} is not a value in {vocab.__vocab_name__}"
        for item in candidates
        if isinstance(item, str) and not vocab.contains(item)
    ]


def _nested_warnings(value: Any, loc: str) -> list[str]:  # noqa: ANN401
    if isinstance(value, BaseModel):
        return open_vocab_warnings(value, f"{loc}.")
    warnings: list[str] = []
    if isinstance(value, list):
        for i, item in enumerate(value):
            warnings.extend(_nested_warnings(item, f"{loc}.{i}"))
    elif isinstance(value, dict):
        for key, item in value.items():
            warnings.extend(_nested_warnings(item, f"{loc}.{key}"))
    return warnings


def open_vocab_warnings(model: BaseModel, path: str = "") -> list[str]:
    """Return a warning for every open-vocabulary value in ``model`` that is not in its vocabulary.

    Nested models (extensions, sub-objects) are checked recursively; ``path`` prefixes the
    reported location. Comparison is case-sensitive.
    """
    warnings: list[str] = []
    for name, field in type(model).model_fields.items():
        value = getattr(model, name)
        if value is None:
            continue
        loc = f"{path}{field.alias or name}"
        marker = _find_marker(field)
        if marker is not None:
            warnings.extend(_check_value(marker, value, loc))
        warnings.extend(_nested_warnings(value, loc))
    return warnings
