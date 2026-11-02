# stix2-utils
A utility library for working with STIX 2.1 objects. This library implements Pydantic models to parse and validate STIX 2.1 objects. It also includes a custom parser for reading STIX 2.1 indicator patterns which outputs the pattern in a typed Abstract Syntax Tree. 

This library is currently in active development, and is subject to change. It is possible that there are mistakes or missing aspects in the implementation of the STIX 2.1 spec.

## Installation
The stix2-utils library is hosted on PyPi. The most recent version can be installed with pip:

```bash
pip install stix2-utils
```

## Usage

### Parsing & Validating
You can use the library to validate STIX 2.1 objects and receive human readable errors

```python
validator = STIX2Validator()
validation_result = validator.validate_entity(stix_obj)

print(validation_result.is_valid)
print(validation_result.errors)
```

The object is available in the validation result under the .obj key. If the input was not valid, the .obj will be None. 

Additionally the validator also returns a list of warnings. A warning is generated when the object does not follow the 'shoulds' defined in the STIX 2.1 specification.


```python
print(validation_result.warnings)
```

#### Open vocabularies
Many STIX 2.1 properties take their values from an *open vocabulary* (section 10 of the specification), for example `indicator_types` (`indicator-type-ov`), `malware_types` (`malware-type-ov`) or the keys of a `hashes` dictionary (`hash-algorithm-ov`). The specification says these values SHOULD come from the vocabulary but allows custom values, so a value outside the vocabulary is reported as a **warning**; the object stays valid. The comparison is case-sensitive, so `Malicious-Activity` is reported just like any other unknown value.

```python
validation_result = validator.validate_entity(
    {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "created": "2024-01-15T08:00:00.000Z",
        "modified": "2024-01-15T08:00:00.000Z",
        "name": "Example",
        "is_family": True,
        "malware_types": ["ransomware", "cryptominer"],
    }
)

print(validation_result.is_valid)  # True
print(validation_result.warnings[0].description)
# malware_types: 'cryptominer' is not a value in malware-type-ov
```

Warnings for nested properties include the full path (e.g. `extensions.windows-pebinary-ext.pe_type`), and warnings for objects inside a bundle are prefixed with `objects.N (id)`.

All open vocabularies are available as `StrEnum`s in `stix2utils.vocabs`:

```python
from stix2utils.vocabs import IndicatorTypeOv

IndicatorTypeOv.MALICIOUS_ACTIVITY  # "malicious-activity"
IndicatorTypeOv.contains("benign")  # True
IndicatorTypeOv.__vocab_name__  # "indicator-type-ov"
```

### Supported objects
The validator accepts every STIX 2.1 SDO, SCO and SRO, the Marking Definition, Extension Definition and Language Content meta objects, and Bundles.

Custom objects (types starting with `x-`, deprecated since STIX 2.1 in favour of extension definitions) are not supported: an object with an unknown `type` is reported as invalid, and so is a Bundle that contains one. Custom properties should be added through the `extensions` property, whose keys must be an `extension-definition--<uuid>` id (or a deprecated `x-` name).

### Custom properties
By default the validator rejects any property that is not defined in the STIX 2.1 specification, such as custom `x_*` properties, and reports it as an error.

```python
validator = STIX2Validator()  # allow_custom=False by default
result = validator.validate_entity({..., "x_custom_score": 7})
print(result.errors)  # [... x_custom_score: Extra inputs are not permitted [extra_forbidden]]
```

Set `allow_custom=True` to accept custom properties. This also applies to nested objects (such as kill chain phases) and to objects inside a bundle. The custom properties are kept on the parsed object and can be read through `model_extra`. Each one is also reported as a warning, so a misspelled property name doesn't slip through unnoticed.

```python
validator = STIX2Validator(allow_custom=True)
result = validator.validate_entity({..., "x_custom_score": 7})
print(result.is_valid)          # True
print(result.obj.model_extra)   # {'x_custom_score': 7}
print(result.warnings)          # [... x_custom_score: custom property is not defined in the STIX 2.1 specification]
```

### Pattern parsing
You can use the STIX 2.1 pattern parser to convert a pattern string into an AST. 


```python
ast = Parser().parse(
    "[ network-traffic:src_ref.value = '203.0.113.10' AND network-traffic:dst_ref.value != '198.51.100.58' OR network-traffic:dst_ref.value = '127.0.0.1' ] OR [ipv4-addr:value = '198.51.100.0']"
)
```
Returns an AST that looks like this:
```
RootExpressionNode (OR)
├── left: ObservationExpressionNode (OR)
│   ├── left: ComparisonExpressionNode (AND)
│   │   ├── left:  ComparisonExpressionNode (EQUALS)
|   |   |   ├── left:  ObjectPathNode  → network-traffic:dst_ref.value
|   |   |   ├── right: ValueNode  → "203.0.113.10" 
│   │   └── right: ComparisonExpressionNode  (NOT_EQUALS)
|   |   |   ├── left:  ObjectPathNode  → network-traffic:dst_ref.value
|   |   |   ├── right: ValueNode  → "198.51.100.58" 
│   └── right: ComparisonExpressionNode (EQUALS)
│       ├── left:  ObjectPathNode  → network-traffic:dst_ref.value
│       └── right: ValueNode       → "127.0.0.1"
└── right: ObservationExpressionNode (EQUALS)
    ├── left:  ObjectPathNode  → network-traffic:dst_ref.value
    └── right: ValueNode       → "198.51.100.0"
```

The resulting AST can be used to extract observable values from patterns, and to evaluate values against the pattern to determine if there is a match.
