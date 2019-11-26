# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Remove duplicate items from an array of strings"


class Input:
    DATA = "data"
    

class Output:
    DUPLICATE_COUNT = "duplicate_count"
    ELEMENT_COUNT = "element_count"
    RESULT = "result"
    

class UniqStringArrayInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "data": {
      "type": "array",
      "title": "Data",
      "description": "Array of strings",
      "items": {
        "type": "string"
      },
      "order": 1
    }
  },
  "required": [
    "data"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class UniqStringArrayOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "duplicate_count": {
      "type": "integer",
      "title": "Duplicate count",
      "description": "Count of duplicates removed",
      "order": 2
    },
    "element_count": {
      "type": "object",
      "title": "Element count",
      "description": "Count of each element",
      "order": 3
    },
    "result": {
      "type": "array",
      "title": "Result",
      "description": "Result without duplicates",
      "items": {
        "type": "string"
      },
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
