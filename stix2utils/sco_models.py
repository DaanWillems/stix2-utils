from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from stix2utils.common import Hashes, Hex, Timestamp
from stix2utils.references import (
    _UUID,
    AnyRef,
    ArtifactRef,
    DirectoryContainsRef,
    DirectoryRef,
    DomainResolvesToRef,
    EmailAddrRef,
    EmailFromRef,
    FileRef,
    IPBelongsToRef,
    IPResolvesToRef,
    MarkingRef,
    MimeBodyRawRef,
    NetworkSrcDstRef,
    NetworkTrafficRef,
    ProcessRef,
    UserAccountRef,
)


class STIXCyberObservable(BaseModel):
    """Common properties shared by all STIX 2.1 SCOs.

    Unlike SDOs, SCOs are not versioned: they do not carry created, modified,
    created_by_ref, revoked, labels, confidence, lang, or external_references.
    """

    model_config = ConfigDict(extra="forbid")

    # Required common properties
    id: str = Field(..., pattern=rf"^[a-z0-9-]+--{_UUID}$")

    # Optional common properties
    spec_version: Literal["2.1"] | None = "2.1"
    object_marking_refs: Annotated[list[MarkingRef], Field(min_length=1)] | None = None
    granular_markings: list[dict] | None = None
    defanged: bool | None = None
    extensions: dict | None = None

    @model_validator(mode="after")
    def _id_prefix_matches_type(self) -> STIXCyberObservable:
        expected = self.type
        prefix = self.id.split("--", 1)[0]
        if prefix != expected:
            msg = f"id prefix {prefix!r} does not match type {expected!r}"
            raise ValueError(msg)
        return self

class EncryptionAlgorithm(str, Enum):
    AES_256_GCM = "AES-256-GCM"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"
    MIME_TYPE_INDICATED = "mime-type-indicated"


class Artifact(STIXCyberObservable):
    type: Literal["artifact"] = "artifact"
    mime_type: str | None = None
    payload_bin: str | None = None  # base64-encoded binary
    url: str | None = None
    hashes: Hashes | None = None
    encryption_algorithm: EncryptionAlgorithm | None = None
    decryption_key: str | None = None

    @model_validator(mode="after")
    def _check_payload_or_url(self) -> Artifact:
        if bool(self.payload_bin) == bool(self.url):
            msg = "exactly one of payload_bin or url MUST be provided"
            raise ValueError(msg)
        if self.url and not self.hashes:
            msg = "hashes MUST be present when url is present"
            raise ValueError(msg)
        if self.payload_bin and self.url:
            msg = "payload_bin MUST NOT be present if url is provided"
            raise ValueError(msg)
        if self.decryption_key and not self.encryption_algorithm:
            msg = "decryption_key MUST NOT be present when encryption_algorithm is absent"
            raise ValueError(msg)
        return self


class AutonomousSystem(STIXCyberObservable):
    type: Literal["autonomous-system"] = "autonomous-system"
    number: int
    name: str | None = None
    rir: str | None = None


class Directory(STIXCyberObservable):
    type: Literal["directory"] = "directory"
    path: str
    path_enc: str | None = None
    ctime: Timestamp | None = None
    mtime: Timestamp | None = None
    atime: Timestamp | None = None
    contains_refs: Annotated[list[DirectoryContainsRef], Field(min_length=1)] | None = None


class DomainName(STIXCyberObservable):
    type: Literal["domain-name"] = "domain-name"
    value: str
    resolves_to_refs: Annotated[list[DomainResolvesToRef], Field(min_length=1)] | None = None


class EmailAddress(STIXCyberObservable):
    type: Literal["email-addr"] = "email-addr"
    value: str
    display_name: str | None = None
    belongs_to_ref: UserAccountRef | None = None


class EmailMIMEComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str | None = None
    body_raw_ref: MimeBodyRawRef | None = None
    content_type: str | None = None
    content_disposition: str | None = None

    @model_validator(mode="after")
    def _check_body_or_raw(self) -> EmailMIMEComponent:
        if not self.body and not self.body_raw_ref:
            msg = "one of body or body_raw_ref MUST be included"
            raise ValueError(msg)
        return self


class EmailMessage(STIXCyberObservable):
    type: Literal["email-message"] = "email-message"
    is_multipart: bool
    date: Timestamp | None = None
    content_type: str | None = None
    from_ref: EmailFromRef | None = None
    sender_ref: EmailAddrRef | None = None
    to_refs: Annotated[list[EmailAddrRef], Field(min_length=1)] | None = None
    cc_refs: Annotated[list[EmailAddrRef], Field(min_length=1)] | None = None
    bcc_refs: Annotated[list[EmailAddrRef], Field(min_length=1)] | None = None
    message_id: str | None = None
    subject: str | None = None
    received_lines: Annotated[list[str], Field(min_length=1)] | None = None
    additional_header_fields: dict | None = None
    body: str | None = None
    body_multipart: Annotated[list[EmailMIMEComponent], Field(min_length=1)] | None = None
    raw_email_ref: ArtifactRef | None = None

    @model_validator(mode="after")
    def _check_multipart(self) -> EmailMessage:
        if self.is_multipart and self.body is not None:
            msg = "body MUST NOT be used if is_multipart is true"
            raise ValueError(msg)
        if not self.is_multipart and self.body_multipart is not None:
            msg = "body_multipart MUST NOT be used if is_multipart is false"
            raise ValueError(msg)
        return self


class AlternateDataStream(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    hashes: Hashes | None = None
    size: Annotated[int, Field(ge=0)] | None = None


class NTFSExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sid: str | None = None
    alternate_data_streams: Annotated[list[AlternateDataStream], Field(min_length=1)] | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> NTFSExt:
        if not any(v is not None for v in (self.sid, self.alternate_data_streams)):
            msg = "NTFS extension MUST contain at least one property"
            raise ValueError(msg)
        return self


class PDFExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str | None = None
    is_optimized: bool | None = None
    document_info_dict: dict | None = None
    pdfid0: str | None = None
    pdfid1: str | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> PDFExt:
        if not any(
            v is not None
            for v in (
                self.version,
                self.is_optimized,
                self.document_info_dict,
                self.pdfid0,
                self.pdfid1,
            )
        ):
            msg = "PDF extension MUST contain at least one property"
            raise ValueError(msg)
        return self


class RasterImageExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    image_height: int | None = None
    image_width: int | None = None
    bits_per_pixel: int | None = None
    exif_tags: dict | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> RasterImageExt:
        if not any(
            v is not None
            for v in (
                self.image_height,
                self.image_width,
                self.bits_per_pixel,
                self.exif_tags,
            )
        ):
            msg = "Raster image extension MUST contain at least one property"
            raise ValueError(msg)
        return self


class ArchiveExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contains_refs: Annotated[list[DirectoryContainsRef], Field(min_length=1)]
    comment: str | None = None


class WindowsPEOptionalHeaderType(BaseModel):
    model_config = ConfigDict(extra="forbid")

    magic_hex: Hex | None = None
    major_linker_version: int | None = None
    minor_linker_version: int | None = None
    size_of_code: Annotated[int, Field(ge=0)] | None = None
    size_of_initialized_data: Annotated[int, Field(ge=0)] | None = None
    size_of_uninitialized_data: Annotated[int, Field(ge=0)] | None = None
    address_of_entry_point: int | None = None
    base_of_code: int | None = None
    base_of_data: int | None = None
    image_base: int | None = None
    section_alignment: int | None = None
    file_alignment: int | None = None
    major_os_version: int | None = None
    minor_os_version: int | None = None
    major_image_version: int | None = None
    minor_image_version: int | None = None
    major_subsystem_version: int | None = None
    minor_subsystem_version: int | None = None
    win32_version_value_hex: Hex | None = None
    size_of_image: Annotated[int, Field(ge=0)] | None = None
    size_of_headers: Annotated[int, Field(ge=0)] | None = None
    checksum_hex: Hex | None = None
    subsystem_hex: Hex | None = None
    dll_characteristics_hex: Hex | None = None
    size_of_stack_reserve: Annotated[int, Field(ge=0)] | None = None
    size_of_stack_commit: Annotated[int, Field(ge=0)] | None = None
    size_of_heap_reserve: Annotated[int, Field(ge=0)] | None = None
    size_of_heap_commit: Annotated[int, Field(ge=0)] | None = None
    loader_flags_hex: Hex | None = None
    number_of_rva_and_sizes: int | None = None
    hashes: Hashes | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> WindowsPEOptionalHeaderType:
        if not any(v is not None for v in self.__dict__.values()):
            msg = "PE optional header MUST contain at least one property"
            raise ValueError(msg)
        return self


class WindowsPESectionType(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    size: Annotated[int, Field(ge=0)] | None = None
    entropy: Annotated[float, Field(ge=0.0, le=8.0)] | None = None
    hashes: Hashes | None = None


class WindowsPEBinaryExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pe_type: str  # windows-pebinary-type-ov (open): dll, exe, sys
    imphash: str | None = None
    machine_hex: Hex | None = None
    number_of_sections: int | None = None
    time_date_stamp: Timestamp | None = None
    pointer_to_symbol_table_hex: Hex | None = None
    number_of_symbols: int | None = None
    size_of_optional_header: Annotated[int, Field(ge=0)] | None = None
    characteristics_hex: Hex | None = None
    file_header_hashes: Hashes | None = None
    optional_header: WindowsPEOptionalHeaderType | None = None
    sections: Annotated[list[WindowsPESectionType], Field(min_length=1)] | None = None


class FileExtensions(BaseModel):
    """Predefined File object extensions."""

    model_config = ConfigDict(extra="allow")  # allow custom / extension-definition keys

    ntfs_ext: NTFSExt | None = Field(default=None, alias="ntfs-ext")
    raster_image_ext: RasterImageExt | None = Field(default=None, alias="raster-image-ext")
    pdf_ext: PDFExt | None = Field(default=None, alias="pdf-ext")
    archive_ext: ArchiveExt | None = Field(default=None, alias="archive-ext")
    windows_pebinary_ext: WindowsPEBinaryExt | None = Field(default=None, alias="windows-pebinary-ext")


class File(STIXCyberObservable):
    type: Literal["file"] = "file"
    hashes: Hashes | None = None
    size: Annotated[int, Field(ge=0)] | None = None
    name: str | None = None
    name_enc: str | None = None
    magic_number_hex: Hex | None = None
    mime_type: str | None = None
    ctime: Timestamp | None = None
    mtime: Timestamp | None = None
    atime: Timestamp | None = None
    parent_directory_ref: DirectoryRef | None = None
    contains_refs: Annotated[list[AnyRef], Field(min_length=1)] | None = None
    content_ref: ArtifactRef | None = None
    extensions: FileExtensions | None = None

    @model_validator(mode="after")
    def _hashes_or_name(self) -> File:
        if not self.hashes and not self.name:
            msg = "File object MUST contain at least one of hashes or name"
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# IPv4 Address
# ---------------------------------------------------------------------------


class IPv4Address(STIXCyberObservable):
    type: Literal["ipv4-addr"] = "ipv4-addr"
    value: str
    resolves_to_refs: Annotated[list[IPResolvesToRef], Field(min_length=1)] | None = None
    belongs_to_refs: Annotated[list[IPBelongsToRef], Field(min_length=1)] | None = None


# ---------------------------------------------------------------------------
# IPv6 Address
# ---------------------------------------------------------------------------


class IPv6Address(STIXCyberObservable):
    type: Literal["ipv6-addr"] = "ipv6-addr"
    value: str
    resolves_to_refs: Annotated[list[IPResolvesToRef], Field(min_length=1)] | None = None
    belongs_to_refs: Annotated[list[IPBelongsToRef], Field(min_length=1)] | None = None


# ---------------------------------------------------------------------------
# MAC Address
# ---------------------------------------------------------------------------


class MACAddress(STIXCyberObservable):
    type: Literal["mac-addr"] = "mac-addr"
    # colon-delimited, lowercase MAC-48 with leading zeros
    value: Annotated[str, Field(pattern=r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")]


# ---------------------------------------------------------------------------
# Mutex
# ---------------------------------------------------------------------------


class Mutex(STIXCyberObservable):
    type: Literal["mutex"] = "mutex"
    name: str


# ---------------------------------------------------------------------------
# Network Traffic  (+ extensions)
# ---------------------------------------------------------------------------

_Port = Annotated[int, Field(ge=0, le=65535)]


class HTTPRequestExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_method: str
    request_value: str
    request_version: str | None = None
    request_header: dict | None = None
    message_body_length: int | None = None
    message_body_data_ref: ArtifactRef | None = None


class ICMPExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    icmp_type_hex: Hex
    icmp_code_hex: Hex


class NetworkSocketAddressFamily(str, Enum):
    AF_UNSPEC = "AF_UNSPEC"
    AF_INET = "AF_INET"
    AF_IPX = "AF_IPX"
    AF_APPLETALK = "AF_APPLETALK"
    AF_NETBIOS = "AF_NETBIOS"
    AF_INET6 = "AF_INET6"
    AF_IRDA = "AF_IRDA"
    AF_BTH = "AF_BTH"


class NetworkSocketType(str, Enum):
    SOCK_STREAM = "SOCK_STREAM"
    SOCK_DGRAM = "SOCK_DGRAM"
    SOCK_RAW = "SOCK_RAW"
    SOCK_RDM = "SOCK_RDM"
    SOCK_SEQPACKET = "SOCK_SEQPACKET"


class NetworkSocketExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address_family: NetworkSocketAddressFamily
    is_blocking: bool | None = None
    is_listening: bool | None = None
    options: dict | None = None
    socket_type: NetworkSocketType | None = None
    socket_descriptor: Annotated[int, Field(ge=0)] | None = None
    socket_handle: int | None = None


class TCPExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    src_flags_hex: Hex | None = None
    dst_flags_hex: Hex | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> TCPExt:
        if self.src_flags_hex is None and self.dst_flags_hex is None:
            msg = "TCP extension MUST contain at least one property"
            raise ValueError(msg)
        return self


class NetworkTrafficExtensions(BaseModel):
    model_config = ConfigDict(extra="allow")

    http_request_ext: HTTPRequestExt | None = Field(default=None, alias="http-request-ext")
    tcp_ext: TCPExt | None = Field(default=None, alias="tcp-ext")
    icmp_ext: ICMPExt | None = Field(default=None, alias="icmp-ext")
    socket_ext: NetworkSocketExt | None = Field(default=None, alias="socket-ext")


class NetworkTraffic(STIXCyberObservable):
    type: Literal["network-traffic"] = "network-traffic"
    start: Timestamp | None = None
    end: Timestamp | None = None
    is_active: bool | None = None
    src_ref: NetworkSrcDstRef | None = None
    dst_ref: NetworkSrcDstRef | None = None
    src_port: _Port | None = None
    dst_port: _Port | None = None
    protocols: Annotated[list[str], Field(min_length=1)]
    src_byte_count: Annotated[int, Field(ge=0)] | None = None
    dst_byte_count: Annotated[int, Field(ge=0)] | None = None
    src_packets: Annotated[int, Field(ge=0)] | None = None
    dst_packets: Annotated[int, Field(ge=0)] | None = None
    ipfix: dict | None = None
    src_payload_ref: ArtifactRef | None = None
    dst_payload_ref: ArtifactRef | None = None
    encapsulates_refs: Annotated[list[NetworkTrafficRef], Field(min_length=1)] | None = None
    encapsulated_by_ref: NetworkTrafficRef | None = None
    extensions: NetworkTrafficExtensions | None = None

    @model_validator(mode="after")
    def _src_or_dst(self) -> NetworkTraffic:
        if self.src_ref is None and self.dst_ref is None:
            msg = "Network Traffic MUST contain at least one of src_ref or dst_ref"
            raise ValueError(msg)
        if self.is_active is True and self.end is not None:
            msg = "end MUST NOT be included if is_active is true (and is_active MUST be false if end is provided)"
            raise ValueError(msg)
        return self


class WindowsIntegrityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SYSTEM = "system"


class WindowsProcessExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    aslr_enabled: bool | None = None
    dep_enabled: bool | None = None
    priority: Annotated[str, Field(pattern=r".*_CLASS$")] | None = None
    owner_sid: str | None = None
    window_title: str | None = None
    startup_info: dict | None = None
    integrity_level: WindowsIntegrityLevel | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> WindowsProcessExt:
        if not any(v is not None for v in self.__dict__.values()):
            msg = "Windows process extension MUST contain at least one property"
            raise ValueError(msg)
        return self


class WindowsServiceStartType(str, Enum):
    SERVICE_AUTO_START = "SERVICE_AUTO_START"
    SERVICE_BOOT_START = "SERVICE_BOOT_START"
    SERVICE_DEMAND_START = "SERVICE_DEMAND_START"
    SERVICE_DISABLED = "SERVICE_DISABLED"
    SERVICE_SYSTEM_ALERT = "SERVICE_SYSTEM_ALERT"


class WindowsServiceType(str, Enum):
    SERVICE_KERNEL_DRIVER = "SERVICE_KERNEL_DRIVER"
    SERVICE_FILE_SYSTEM_DRIVER = "SERVICE_FILE_SYSTEM_DRIVER"
    SERVICE_WIN32_OWN_PROCESS = "SERVICE_WIN32_OWN_PROCESS"
    SERVICE_WIN32_SHARE_PROCESS = "SERVICE_WIN32_SHARE_PROCESS"


class WindowsServiceStatus(str, Enum):
    SERVICE_CONTINUE_PENDING = "SERVICE_CONTINUE_PENDING"
    SERVICE_PAUSE_PENDING = "SERVICE_PAUSE_PENDING"
    SERVICE_PAUSED = "SERVICE_PAUSED"
    SERVICE_RUNNING = "SERVICE_RUNNING"
    SERVICE_START_PENDING = "SERVICE_START_PENDING"
    SERVICE_STOP_PENDING = "SERVICE_STOP_PENDING"
    SERVICE_STOPPED = "SERVICE_STOPPED"


class WindowsServiceExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: str | None = None
    descriptions: Annotated[list[str], Field(min_length=1)] | None = None
    display_name: str | None = None
    group_name: str | None = None
    start_type: WindowsServiceStartType | None = None
    service_dll_refs: Annotated[list[FileRef], Field(min_length=1)] | None = None
    service_type: WindowsServiceType | None = None
    service_status: WindowsServiceStatus | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> WindowsServiceExt:
        if not any(v is not None for v in self.__dict__.values()):
            msg = "Windows service extension MUST contain at least one property"
            raise ValueError(msg)
        return self


class ProcessExtensions(BaseModel):
    model_config = ConfigDict(extra="allow")

    windows_process_ext: WindowsProcessExt | None = Field(default=None, alias="windows-process-ext")
    windows_service_ext: WindowsServiceExt | None = Field(default=None, alias="windows-service-ext")


class Process(STIXCyberObservable):
    type: Literal["process"] = "process"
    is_hidden: bool | None = None
    pid: int | None = None
    created_time: Timestamp | None = None
    cwd: str | None = None
    command_line: str | None = None
    environment_variables: dict | None = None
    opened_connection_refs: Annotated[list[NetworkTrafficRef], Field(min_length=1)] | None = None
    creator_user_ref: UserAccountRef | None = None
    image_ref: FileRef | None = None
    parent_ref: ProcessRef | None = None
    child_refs: Annotated[list[ProcessRef], Field(min_length=1)] | None = None
    extensions: ProcessExtensions | None = None

    @model_validator(mode="after")
    def _at_least_one_property(self) -> Process:
        specific = (
            self.is_hidden,
            self.pid,
            self.created_time,
            self.cwd,
            self.command_line,
            self.environment_variables,
            self.opened_connection_refs,
            self.creator_user_ref,
            self.image_ref,
            self.parent_ref,
            self.child_refs,
            self.extensions,
        )
        if not any(v is not None for v in specific):
            msg = "Process object MUST contain at least one property (or extension)"
            raise ValueError(msg)
        return self


class Software(STIXCyberObservable):
    type: Literal["software"] = "software"
    name: str
    cpe: str | None = None
    swid: str | None = None
    languages: Annotated[list[str], Field(min_length=1)] | None = None
    vendor: str | None = None
    version: str | None = None


class URL(STIXCyberObservable):
    type: Literal["url"] = "url"
    value: str


class UNIXAccountExt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gid: int | None = None
    groups: Annotated[list[str], Field(min_length=1)] | None = None
    home_dir: str | None = None
    shell: str | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> UNIXAccountExt:
        if not any(v is not None for v in self.__dict__.values()):
            msg = "UNIX account extension MUST contain at least one property"
            raise ValueError(msg)
        return self


class UserAccountExtensions(BaseModel):
    model_config = ConfigDict(extra="allow")

    unix_account_ext: UNIXAccountExt | None = Field(default=None, alias="unix-account-ext")


class UserAccount(STIXCyberObservable):
    type: Literal["user-account"] = "user-account"
    user_id: str | None = None
    credential: str | None = None
    account_login: str | None = None
    account_type: str | None = None  # account-type-ov (open)
    display_name: str | None = None
    is_service_account: bool | None = None
    is_privileged: bool | None = None
    can_escalate_privs: bool | None = None
    is_disabled: bool | None = None
    account_created: Timestamp | None = None
    account_expires: Timestamp | None = None
    credential_last_changed: Timestamp | None = None
    account_first_login: Timestamp | None = None
    account_last_login: Timestamp | None = None
    extensions: UserAccountExtensions | None = None

    @model_validator(mode="after")
    def _at_least_one_property(self) -> UserAccount:
        specific = (
            self.user_id,
            self.credential,
            self.account_login,
            self.account_type,
            self.display_name,
            self.is_service_account,
            self.is_privileged,
            self.can_escalate_privs,
            self.is_disabled,
            self.account_created,
            self.account_expires,
            self.credential_last_changed,
            self.account_first_login,
            self.account_last_login,
            self.extensions,
        )
        if not any(v is not None for v in specific):
            msg = "User Account object MUST contain at least one property"
            raise ValueError(msg)
        return self


class WindowsRegistryDatatype(str, Enum):
    REG_NONE = "REG_NONE"
    REG_SZ = "REG_SZ"
    REG_EXPAND_SZ = "REG_EXPAND_SZ"
    REG_BINARY = "REG_BINARY"
    REG_DWORD = "REG_DWORD"
    REG_DWORD_BIG_ENDIAN = "REG_DWORD_BIG_ENDIAN"
    REG_DWORD_LITTLE_ENDIAN = "REG_DWORD_LITTLE_ENDIAN"
    REG_LINK = "REG_LINK"
    REG_MULTI_SZ = "REG_MULTI_SZ"
    REG_RESOURCE_LIST = "REG_RESOURCE_LIST"
    REG_FULL_RESOURCE_DESCRIPTION = "REG_FULL_RESOURCE_DESCRIPTION"
    REG_RESOURCE_REQUIREMENTS_LIST = "REG_RESOURCE_REQUIREMENTS_LIST"
    REG_QWORD = "REG_QWORD"
    REG_INVALID_TYPE = "REG_INVALID_TYPE"


class WindowsRegistryValueType(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    data: str | None = None
    data_type: WindowsRegistryDatatype | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> WindowsRegistryValueType:
        if not any(v is not None for v in self.__dict__.values()):
            msg = "Windows registry value type MUST contain at least one property"
            raise ValueError(msg)
        return self


class WindowsRegistryKey(STIXCyberObservable):
    type: Literal["windows-registry-key"] = "windows-registry-key"
    key: str | None = None
    values: Annotated[list[WindowsRegistryValueType], Field(min_length=1)] | None = None
    modified_time: Timestamp | None = None
    creator_user_ref: UserAccountRef | None = None
    number_of_subkeys: int | None = None

    @model_validator(mode="after")
    def _at_least_one_property(self) -> WindowsRegistryKey:
        specific = (
            self.key,
            self.values,
            self.modified_time,
            self.creator_user_ref,
            self.number_of_subkeys,
        )
        if not any(v is not None for v in specific):
            msg = "Windows Registry Key object MUST contain at least one property"
            raise ValueError(msg)
        return self


class X509V3ExtensionsType(BaseModel):
    model_config = ConfigDict(extra="forbid")

    basic_constraints: str | None = None
    name_constraints: str | None = None
    policy_constraints: str | None = None
    key_usage: str | None = None
    extended_key_usage: str | None = None
    subject_key_identifier: str | None = None
    authority_key_identifier: str | None = None
    subject_alternative_name: str | None = None
    issuer_alternative_name: str | None = None
    subject_directory_attributes: str | None = None
    crl_distribution_points: str | None = None
    inhibit_any_policy: str | None = None
    private_key_usage_period_not_before: Timestamp | None = None
    private_key_usage_period_not_after: Timestamp | None = None
    certificate_policies: str | None = None
    policy_mappings: str | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> X509V3ExtensionsType:
        if not any(v is not None for v in self.__dict__.values()):
            msg = "X.509 v3 extensions type MUST contain at least one property"
            raise ValueError(msg)
        return self


class X509Certificate(STIXCyberObservable):
    type: Literal["x509-certificate"] = "x509-certificate"
    is_self_signed: bool | None = None
    hashes: Hashes | None = None
    version: str | None = None
    serial_number: str | None = None
    signature_algorithm: str | None = None
    issuer: str | None = None
    validity_not_before: Timestamp | None = None
    validity_not_after: Timestamp | None = None
    subject: str | None = None
    subject_public_key_algorithm: str | None = None
    subject_public_key_modulus: str | None = None
    subject_public_key_exponent: int | None = None
    x509_v3_extensions: X509V3ExtensionsType | None = None

    @model_validator(mode="after")
    def _at_least_one_property(self) -> X509Certificate:
        specific = (
            self.is_self_signed,
            self.hashes,
            self.version,
            self.serial_number,
            self.signature_algorithm,
            self.issuer,
            self.validity_not_before,
            self.validity_not_after,
            self.subject,
            self.subject_public_key_algorithm,
            self.subject_public_key_modulus,
            self.subject_public_key_exponent,
            self.x509_v3_extensions,
        )
        if not any(v is not None for v in specific):
            msg = "X.509 Certificate object MUST contain at least one specific property"
            raise ValueError(msg)
        return self
