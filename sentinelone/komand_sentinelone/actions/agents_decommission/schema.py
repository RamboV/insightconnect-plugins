# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Decommissions all agents matching the input filter"


class Input:
    FILTER = "filter"
    

class Output:
    AFFECTED = "affected"
    

class AgentsDecommissionInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "filter": {
      "type": "object",
      "title": "Filter Json",
      "description": "Applied filter - only matched agents will be affected by the requested action. Note - one of the following filter arguments must be supplied - ids, groupIds, filterId",
      "order": 1
    }
  },
  "required": [
    "filter"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class AgentsDecommissionOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "affected": {
      "type": "integer",
      "title": "Affected",
      "description": "Number of entities affected by the requested operation",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
