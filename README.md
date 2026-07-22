# stix2-utils
A utility library for validating STIX 2.1 objects. This library implements Pydantic models to validate STIX 2.1 objects. It also includes a custom parser for reading STIX 2.1 indicator patterns which outputs the pattern in a typed Abstract Syntax Tree. 

## Installation
The stix2-utils library is hosted on PyPi. The most recent version can be installed with pip:

```bash
pip install stix2-utils
```

## Usage

### Validating
You can use the library to validate STIX 2.1 objects and receive human readable errors

```python
validator = STIX2Validator()
validation_result = validator.validate_entity(stix_obj)

print(validation_result.success)
print(validation_result.errors)
```

### Pattern parsing
You can use the STIX 2.1 pattern parser to convert a pattern string into an AST. 


```python
    ast = Parser().process("[ network-traffic:src_ref.value = '203.0.113.10' AND network-traffic:dst_ref.value != '198.51.100.58' OR network-traffic:dst_ref.value = '127.0.0.1' ]")
```
Returns an AST that looks like this:
```
ExpressionNode (OR)
├── left: ExpressionNode (AND)
│   ├── left: ExpressionNode (EQUALS)
│   │   ├── left:  ObjectPathNode  → network-traffic:src_ref.value
│   │   └── right: ValueNode       → "203.0.113.10"
│   └── right: ExpressionNode (NOT_EQUALS)
│       ├── left:  ObjectPathNode  → network-traffic:dst_ref.value
│       └── right: ValueNode       → "198.51.100.58"
└── right: ExpressionNode (EQUALS)
    ├── left:  ObjectPathNode  → network-traffic:dst_ref.value
    └── right: ValueNode       → "127.0.0.1"
```