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
