# coding: utf-8

"""
    Echo Server API

    Echo Server API

    The version of the OpenAPI document: 0.1.0
    Contact: team@openapitools.org
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


from __future__ import annotations
import pprint
import re  # noqa: F401
import json


from typing import List, Optional
from pydantic import BaseModel, StrictInt, StrictStr, conlist, validator
from openapi_client.models.string_enum_ref import StringEnumRef

class DefaultValue(BaseModel):
    """
    to test the default value of properties  # noqa: E501
    """
    array_string_enum_ref_default: Optional[conlist(StringEnumRef)] = None
    array_string_enum_default: Optional[conlist(StrictStr)] = None
    array_string_default: Optional[conlist(StrictStr)] = None
    array_integer_default: Optional[conlist(StrictInt)] = None
    array_string: Optional[conlist(StrictStr)] = None
    array_string_nullable: Optional[conlist(StrictStr)] = None
    array_string_extension_nullable: Optional[conlist(StrictStr)] = None
    string_nullable: Optional[StrictStr] = None
    __properties = ["array_string_enum_ref_default", "array_string_enum_default", "array_string_default", "array_integer_default", "array_string", "array_string_nullable", "array_string_extension_nullable", "string_nullable"]

    @validator('array_string_enum_default')
    def array_string_enum_default_validate_enum(cls, value):
        """Validates the enum"""
        if value is None:
            return value

        for i in value:
            if i not in ('success', 'failure', 'unclassified',):
                raise ValueError("each list item must be one of ('success', 'failure', 'unclassified')")
        return value

    class Config:
        """Pydantic configuration"""
        allow_population_by_field_name = True
        validate_assignment = True

    def to_str(self) -> str:
        """Returns the string representation of the model using alias"""
        return pprint.pformat(self.dict(by_alias=True))

    def to_json(self) -> str:
        """Returns the JSON representation of the model using alias"""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> DefaultValue:
        """Create an instance of DefaultValue from a JSON string"""
        return cls.from_dict(json.loads(json_str))

    def to_dict(self):
        """Returns the dictionary representation of the model using alias"""
        _dict = self.dict(by_alias=True,
                          exclude={
                          },
                          exclude_none=True)
        # set to None if array_string_nullable (nullable) is None
        # and __fields_set__ contains the field
        if self.array_string_nullable is None and "array_string_nullable" in self.__fields_set__:
            _dict['array_string_nullable'] = None

        # set to None if array_string_extension_nullable (nullable) is None
        # and __fields_set__ contains the field
        if self.array_string_extension_nullable is None and "array_string_extension_nullable" in self.__fields_set__:
            _dict['array_string_extension_nullable'] = None

        # set to None if string_nullable (nullable) is None
        # and __fields_set__ contains the field
        if self.string_nullable is None and "string_nullable" in self.__fields_set__:
            _dict['string_nullable'] = None

        return _dict

    @classmethod
    def from_dict(cls, obj: dict) -> DefaultValue:
        """Create an instance of DefaultValue from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return DefaultValue.parse_obj(obj)

        _obj = DefaultValue.parse_obj({
            "array_string_enum_ref_default": obj.get("array_string_enum_ref_default"),
            "array_string_enum_default": obj.get("array_string_enum_default"),
            "array_string_default": obj.get("array_string_default"),
            "array_integer_default": obj.get("array_integer_default"),
            "array_string": obj.get("array_string"),
            "array_string_nullable": obj.get("array_string_nullable"),
            "array_string_extension_nullable": obj.get("array_string_extension_nullable"),
            "string_nullable": obj.get("string_nullable")
        })
        return _obj


