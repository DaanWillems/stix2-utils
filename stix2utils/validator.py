from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from stix2utils.adapter import stix_adapter
from stix2utils.sco_models import STIXCyberObservable
from stix2utils.sdo_models import STIXDomainObject
from stix2utils.sro_models import STIXRelationshipObject


@dataclass
class STIX2ValidationError:
    description: str


@dataclass
class STIX2ValidationResult:
    is_valid: bool
    obj: STIXDomainObject | STIXCyberObservable | STIXRelationshipObject | None = None
    errors: list[STIX2ValidationError] = field(default_factory=list)


class STIX2Validator:
    def validate_entity(self, obj: dict[str, Any]) -> STIX2ValidationResult:
        try:
            result_object = stix_adapter.validate_python(obj)
        except ValidationError as e:
            stix2_validation_errors = []

            for err in e.errors():
                loc = ".".join(str(x) for x in err["loc"]) or "(root)"
                stix2_validation_errors.append(STIX2ValidationError(description=f"{loc}: {err['msg']} [{err['type']}]"))

            return STIX2ValidationResult(is_valid=False, errors=stix2_validation_errors)
        return STIX2ValidationResult(is_valid=True, obj=result_object)
