from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from stix2utils.adapter import Bundle, STIXObject, stix_toplevel_adapter


@dataclass
class STIX2ValidationError:
    description: str


@dataclass
class STIX2ValidationWarning:
    description: str


@dataclass
class STIX2ValidationResult:
    is_valid: bool
    obj: STIXObject | Bundle | None = None
    errors: list[STIX2ValidationError] = field(default_factory=list)
    warnings: list[STIX2ValidationWarning] = field(default_factory=list)


class STIX2Validator:
    """Validates STIX 2.1 objects and bundles.

    Args:
        strict: When ``True`` (the default), properties that are not defined in the
            STIX 2.1 specification (e.g. custom ``x_*`` properties) are rejected with an
            ``extra_forbidden`` error. When ``False``, such additional properties are
            accepted, including on nested objects and objects inside a bundle, and are
            available on the parsed object via ``model_extra``.
    """

    def __init__(self, *, strict: bool = True) -> None:
        self.strict = strict

    def validate_entity(self, obj: dict[str, Any]) -> STIX2ValidationResult:
        try:
            result_object: STIXObject | Bundle = stix_toplevel_adapter.validate_python(obj, extra="forbid" if self.strict else "allow")
        except ValidationError as e:
            stix2_validation_errors = []

            for err in e.errors():
                loc = ".".join(str(x) for x in err["loc"]) or "(root)"
                stix2_validation_errors.append(STIX2ValidationError(description=f"{loc}: {err['msg']} [{err['type']}]"))

            return STIX2ValidationResult(is_valid=False, errors=stix2_validation_errors)
        warnings = [STIX2ValidationWarning(warning) for warning in result_object.should()]
        return STIX2ValidationResult(is_valid=True, obj=result_object, warnings=warnings)
