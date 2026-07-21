# stix2-utils
A utility library for validating STIX 2.1 objects. This library used pydantic to validate STIX 2.1 objects. Later on it will also support creating objects and validating indicator patterns.

## Installation
The stix2-utils library is hosted on PyPi. The most recent version can be installed with pip:

```bash
pip install stix2-utils
```

## Usage
You can use the library to validate STIX 2.1 objects and receive human readable errors

```python
validator = STIX2Validator()
validation_result = validator.validate_entity(stix_obj)

print(validation_result.success)
print(validation_result.errors)
```
