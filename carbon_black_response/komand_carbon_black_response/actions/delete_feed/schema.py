# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Deletes a feed"


class Input:
    FORCE = "force"
    ID = "id"
    

class Output:
    SUCCESS = "success"
    

class DeleteFeedInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "force": {
      "type": "boolean",
      "title": "Force",
      "description": "Force deletion of all matches if multiple matches found",
      "order": 2
    },
    "id": {
      "type": "string",
      "title": "ID",
      "description": "The ID of the feed",
      "order": 1
    }
  },
  "required": [
    "force",
    "id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class DeleteFeedOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "success": {
      "type": "boolean",
      "title": "Success",
      "description": "Whether or not the deletion was successful",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
