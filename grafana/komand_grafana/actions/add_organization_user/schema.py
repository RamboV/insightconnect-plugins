# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Add a global user to the organization"


class Input:
    LOGIN_OR_EMAIL = "login_or_email"
    ORGANIZATION_ID = "organization_id"
    ROLE = "role"
    

class Output:
    MESSAGE = "message"
    SUCCESS = "success"
    

class AddOrganizationUserInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "login_or_email": {
      "type": "string",
      "title": "Username or Email ID",
      "description": "Username or Email ID of the global user",
      "order": 2
    },
    "organization_id": {
      "type": "integer",
      "title": "Organization ID",
      "description": "Unique ID of the organization eg. 123 (-1 implies current)",
      "default": -1,
      "order": 1
    },
    "role": {
      "type": "string",
      "title": "User Role",
      "description": "Role for the global user in the organization",
      "enum": [
        "Admin",
        "Editor",
        "Viewer"
      ],
      "order": 3
    }
  },
  "required": [
    "login_or_email",
    "role"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class AddOrganizationUserOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "message": {
      "type": "string",
      "title": "Message",
      "description": "Grafana API response, if any",
      "order": 2
    },
    "success": {
      "type": "boolean",
      "title": "Success",
      "description": "True, if the user was added",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
