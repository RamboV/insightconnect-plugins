# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Input:
    FILENAME = "filename"
    QUERY_TYPE = "query_type"
    YEAR = "year"
    

class Output:
    RESPONSE = "response"
    

class ReportInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "filename": {
      "type": "string",
      "title": "Filename",
      "description": "Indicator to search e.g. C5_APT_C2InTheFifthDomain.pdf",
      "order": 1
    },
    "query_type": {
      "type": "string",
      "title": "Query Type",
      "description": "Query Type",
      "enum": [
        "Domains",
        "Hosts",
        "Emails",
        "Samples"
      ],
      "order": 3
    },
    "year": {
      "type": "string",
      "title": "Year",
      "description": "Year to search e.g. 2013",
      "order": 2
    }
  },
  "required": [
    "year",
    "query_type",
    "filename"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class ReportOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "response": {
      "$ref": "#/definitions/response",
      "title": "Response",
      "description": "Response",
      "order": 1
    }
  },
  "definitions": {
    "response": {
      "type": "object",
      "title": "response",
      "properties": {
        "results": {
          "type": "array",
          "title": "Results",
          "description": "Results",
          "items": {
            "type": "object"
          },
          "order": 3
        },
        "status_code": {
          "type": "integer",
          "title": "Status Code",
          "description": "Status Code",
          "order": 1
        },
        "status_message": {
          "type": "string",
          "title": "Status Message",
          "description": "Status message",
          "order": 2
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
