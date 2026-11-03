from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError

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


def _custom_property_warnings(value: object, path: str = "") -> list[str]:
    """Collect a warning for every custom property found on ``value`` or any model nested inside it."""
    prefix = f"{path}." if path else ""

    if isinstance(value, BaseModel):
        warnings: list[str] = []
        # Models declared with extra="allow" (e.g. extension dictionaries) accept
        # extra keys by design, so those keys are not custom properties.
        if type(value).model_config.get("extra") != "allow":
            warnings.extend(
                f"{prefix}{name}: custom property is not defined in the STIX 2.1 specification" for name in (value.model_extra or {})
            )
        for name, info in type(value).model_fields.items():
            warnings.extend(_custom_property_warnings(getattr(value, name), f"{prefix}{info.alias or name}"))
        return warnings

    if isinstance(value, (list, tuple)):
        return [w for i, item in enumerate(value) for w in _custom_property_warnings(item, f"{prefix}{i}")]

    if isinstance(value, dict):
        return [w for key, item in value.items() for w in _custom_property_warnings(item, f"{prefix}{key}")]

    return []


class STIX2Validator:
    """Validates STIX 2.1 objects and bundles.

    Args:
        allow_custom: When ``False`` (the default), properties that are not defined in the
            STIX 2.1 specification (e.g. custom ``x_*`` properties) are rejected with an
            ``extra_forbidden`` error. When ``True``, such properties are accepted, including
            on nested objects and objects inside a bundle. They are available on the parsed
            object via ``model_extra``, and each one is reported as a warning so typos in
            property names do not go unnoticed.
    """

    def __init__(self, *, allow_custom: bool = False) -> None:
        self.allow_custom = allow_custom

    def validate_entity(self, obj: dict[str, Any]) -> STIX2ValidationResult:
        try:
            # Only override the models' own ``extra`` setting when custom properties are
            # allowed. Passing extra="forbid" otherwise would also override models that
            # accept extra keys by design, such as the extension-definition keys of
            # PredefinedExtensions.
            result_object: STIXObject | Bundle = stix_toplevel_adapter.validate_python(obj, extra="allow" if self.allow_custom else None)
        except ValidationError as e:
            stix2_validation_errors = []

            for err in e.errors():
                loc = ".".join(str(x) for x in err["loc"]) or "(root)"
                stix2_validation_errors.append(STIX2ValidationError(description=f"{loc}: {err['msg']} [{err['type']}]"))

            return STIX2ValidationResult(is_valid=False, errors=stix2_validation_errors)
        warnings = [STIX2ValidationWarning(warning) for warning in result_object.should()]
        if self.allow_custom:
            warnings.extend(STIX2ValidationWarning(warning) for warning in _custom_property_warnings(result_object))
        return STIX2ValidationResult(is_valid=True, obj=result_object, warnings=warnings)
