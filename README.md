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