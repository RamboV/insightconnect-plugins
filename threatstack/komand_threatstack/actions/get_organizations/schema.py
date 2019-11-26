# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Get organizations"


class Input:
    FIELDS = "fields"
    

class Output:
    COUNT = "count"
    ORGANIZATIONS = "organizations"
    

class GetOrganizationsInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "fields": {
      "type": "array",
      "title": "Fields",
      "description": "Fields to return",
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


class GetOrganizationsOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "count": {
      "type": "integer",
      "title": "Count",
      "description": "Number of organizations",
      "order": 2
    },
    "organizations": {
      "type": "array",
      "title": "Organizations",
      "description": "Array of organizations",
      "items": {
        "type": "object"
      },
      "order": 1
    }
  },
  "required": [
    "count",
    "organizations"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
