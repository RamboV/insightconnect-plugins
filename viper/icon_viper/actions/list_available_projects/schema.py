# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "List existing projects"


class Input:
    pass

class Output:
    PROJECTS = "projects"
    

class ListAvailableProjectsInput(komand.Input):
    schema = json.loads("""
   {}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class ListAvailableProjectsOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "projects": {
      "type": "array",
      "title": "Available Projects",
      "description": "Available projects",
      "items": {
        "$ref": "#/definitions/Project"
      },
      "order": 1
    }
  },
  "required": [
    "projects"
  ],
  "definitions": {
    "Project": {
      "type": "object",
      "title": "Project",
      "properties": {
        "name": {
          "type": "string",
          "title": "Name",
          "description": "Project name",
          "order": 1
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
