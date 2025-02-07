# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Monitor and retrieve the latest logs"


class Input:
    TOKEN = "token"
    

class State:
    pass

class Output:
    DATA = "data"
    

class MonitorSiemLogsInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "token": {
      "type": "string",
      "title": "Token",
      "description": "Used to request the next available log file",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class MonitorSiemLogsState(insightconnect_plugin_runtime.State):
    schema = json.loads("""
   {}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class MonitorSiemLogsOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "array",
  "title": "Variables",
  "properties": {
    "data": {
      "type": "array",
      "title": "Data",
      "description": "List of logs",
      "items": {
        "type": "object"
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
