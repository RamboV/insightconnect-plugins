# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Get a specific log from an account"


class Input:
    ID = "id"
    

class Output:
    LOG = "log"
    

class GetALogInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "id": {
      "type": "string",
      "title": "ID",
      "description": "Query ID",
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


class GetALogOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "log": {
      "$ref": "#/definitions/logsets_info",
      "title": "Log",
      "description": "Requested log",
      "order": 1
    }
  },
  "required": [
    "log"
  ],
  "definitions": {
    "links": {
      "type": "object",
      "title": "links",
      "properties": {
        "href": {
          "type": "string",
          "title": "HREF",
          "description": "HREF",
          "order": 1
        },
        "rel": {
          "type": "string",
          "title": "REL",
          "description": "REL",
          "order": 2
        }
      }
    },
    "logsets_info": {
      "type": "object",
      "title": "logsets_info",
      "properties": {
        "id": {
          "type": "string",
          "title": "ID",
          "description": "ID",
          "order": 1
        },
        "links": {
          "type": "array",
          "title": "Links",
          "description": "Links",
          "items": {
            "$ref": "#/definitions/links"
          },
          "order": 2
        },
        "name": {
          "type": "string",
          "title": "Name",
          "description": "Name",
          "order": 3
        },
        "rrn": {
          "type": "string",
          "title": "RRN",
          "description": "RRN",
          "order": 4
        },
        "user_data": {
          "$ref": "#/definitions/user_data",
          "title": "User Data",
          "description": "User data",
          "order": 5
        }
      },
      "definitions": {
        "links": {
          "type": "object",
          "title": "links",
          "properties": {
            "href": {
              "type": "string",
              "title": "HREF",
              "description": "HREF",
              "order": 1
            },
            "rel": {
              "type": "string",
              "title": "REL",
              "description": "REL",
              "order": 2
            }
          }
        },
        "user_data": {
          "type": "object",
          "title": "user_data",
          "properties": {
            "platform_managed": {
              "type": "string",
              "title": "Platform Managed",
              "description": "Platform managed",
              "order": 1
            }
          }
        }
      }
    },
    "user_data": {
      "type": "object",
      "title": "user_data",
      "properties": {
        "platform_managed": {
          "type": "string",
          "title": "Platform Managed",
          "description": "Platform managed",
          "order": 1
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
