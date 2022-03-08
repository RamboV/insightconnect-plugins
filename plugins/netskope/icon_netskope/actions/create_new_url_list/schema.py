# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Create a new URL list configuration"


class Input:
    NAME = "name"
    TYPE = "type"
    URLS = "urls"
    

class Output:
    DATA = "data"
    ID = "id"
    MODIFY_BY = "modify_by"
    MODIFY_TIME = "modify_time"
    MODIFY_TYPE = "modify_type"
    NAME = "name"
    PENDING = "pending"
    

class CreateNewUrlListInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "name": {
      "type": "string",
      "title": "Name",
      "description": "Name of new URL list",
      "order": 1
    },
    "type": {
      "type": "string",
      "title": "URL List Category",
      "description": "Category of URL list",
      "enum": [
        "exact",
        "regex"
      ],
      "order": 3
    },
    "urls": {
      "type": "array",
      "title": "URLs",
      "description": "List of URLs",
      "items": {
        "type": "string"
      },
      "order": 2
    }
  },
  "required": [
    "name",
    "type",
    "urls"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class CreateNewUrlListOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "data": {
      "$ref": "#/definitions/data",
      "title": "Data",
      "description": "Data containing URLs and type",
      "order": 3
    },
    "id": {
      "type": "integer",
      "title": "ID",
      "description": "URL list identifier",
      "order": 1
    },
    "modify_by": {
      "type": "string",
      "title": "Modify By",
      "description": "Name of the URL list modifier",
      "order": 5
    },
    "modify_time": {
      "type": "string",
      "title": "Modify Time",
      "displayType": "date",
      "description": "Last URL list modification time",
      "format": "date-time",
      "order": 6
    },
    "modify_type": {
      "type": "string",
      "title": "Modify Type",
      "description": "Shows last modification type. Expected values are Created, Edited, Deleted",
      "order": 4
    },
    "name": {
      "type": "string",
      "title": "Name",
      "description": "URL list name",
      "order": 2
    },
    "pending": {
      "type": "integer",
      "title": "Pending",
      "description": "URL list status of pending (1) and applied (0)",
      "order": 7
    }
  },
  "required": [
    "data",
    "id",
    "modify_by",
    "modify_time",
    "modify_type",
    "name",
    "pending"
  ],
  "definitions": {
    "data": {
      "type": "object",
      "title": "data",
      "properties": {
        "json_version": {
          "type": "integer",
          "title": "JSON version",
          "description": "Current version of JSON format",
          "order": 3
        },
        "type": {
          "type": "string",
          "title": "URL List Category",
          "description": "Category of URL list",
          "order": 2
        },
        "urls": {
          "type": "array",
          "title": "URLs",
          "description": "List of URLs",
          "items": {
            "type": "string"
          },
          "order": 1
        }
      },
      "required": [
        "type",
        "urls"
      ]
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
