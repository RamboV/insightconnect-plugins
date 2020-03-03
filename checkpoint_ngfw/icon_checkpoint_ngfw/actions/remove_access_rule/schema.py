# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Remove access rule"


class Input:
    ACCESS_RULE_NAME = "access_rule_name"
    DISCARD_OTHER_SESSIONS = "discard_other_sessions"
    LAYER = "layer"
    

class Output:
    MESSAGE = "message"
    SUCCESS = "success"
    

class RemoveAccessRuleInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "access_rule_name": {
      "type": "string",
      "title": "Access Rule Name",
      "description": "Access rule name",
      "order": 1
    },
    "discard_other_sessions": {
      "type": "boolean",
      "title": "Discard Other Sessions",
      "description": "Discard all other user sessions. This can fix errors when objects are locked by other sessions",
      "default": true,
      "order": 3
    },
    "layer": {
      "type": "string",
      "title": "Layer",
      "description": "Layer",
      "default": "Network",
      "order": 2
    }
  },
  "required": [
    "access_rule_name",
    "discard_other_sessions",
    "layer"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class RemoveAccessRuleOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "message": {
      "type": "string",
      "title": "Message",
      "description": "Remove operation status",
      "order": 1
    },
    "success": {
      "type": "boolean",
      "title": "Success",
      "description": "Success",
      "order": 2
    }
  },
  "required": [
    "message",
    "success"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
