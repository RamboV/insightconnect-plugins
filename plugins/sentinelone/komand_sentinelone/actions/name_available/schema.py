# GENERATED BY INSIGHT-PLUGIN - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Is the account name available for this account"


class Input:
    NAME = "name"


class Output:
    AVAILABLE = "available"


class NameAvailableInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "name": {
      "type": "string",
      "title": "Name",
      "description": "Account Name to validate",
      "order": 1
    }
  },
  "required": [
    "name"
  ],
  "definitions": {}
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class NameAvailableOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "available": {
      "type": "boolean",
      "title": "Available",
      "description": "Account Name to validate",
      "order": 1
    }
  },
  "required": [
    "available"
  ],
  "definitions": {}
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)