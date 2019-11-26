# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "SQL query"


class Input:
    PARAMETERS = "parameters"
    QUERY = "query"
    

class Output:
    HEADER = "header"
    RESULTS = "results"
    STATUS = "status"
    

class QueryInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "parameters": {
      "type": "object",
      "title": "Parameters",
      "description": "Parameters for query",
      "order": 2
    },
    "query": {
      "type": "string",
      "title": "Query",
      "description": "Query to run",
      "order": 1
    }
  },
  "required": [
    "query"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class QueryOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "header": {
      "type": "array",
      "title": "Header",
      "description": "Array of header fields for the columns",
      "items": {
        "type": "string"
      },
      "order": 2
    },
    "results": {
      "type": "array",
      "title": "Results",
      "description": "Result rows, each as an object with header keys",
      "items": {
        "type": "object"
      },
      "order": 3
    },
    "status": {
      "type": "string",
      "title": "Status",
      "description": "Status message",
      "order": 1
    }
  },
  "required": [
    "status"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
