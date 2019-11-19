# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Close a task"


class Input:
    ID = "id"
    

class Output:
    MESSAGE = "message"
    

class CloseInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "id": {
      "type": "string",
      "title": "ID",
      "description": "Task ID",
      "order": 1
    }
  },
  "required": [
    "id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class CloseOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "message": {
      "type": "string",
      "title": "Message",
      "description": "When user is assigned message is: Task closed",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
