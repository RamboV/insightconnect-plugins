# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Update a document"


class Input:
    _ID = "_id"
    _INDEX = "_index"
    _SOURCE = "_source"
    _TYPE = "_type"
    _VERSION = "_version"
    PARENT = "parent"
    REFRESH = "refresh"
    RETRY_ON_CONFLICT = "retry_on_conflict"
    ROUTING = "routing"
    SCRIPT = "script"
    TIMEOUT = "timeout"
    WAIT_FOR_ACTIVE_SHARDS = "wait_for_active_shards"
    

class Output:
    UPDATE_RESPONSE = "update_response"
    

class UpdateDocumentInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "_id": {
      "type": "string",
      "title": "ID",
      "description": "Optional ID of Indexed Document",
      "order": 3
    },
    "_index": {
      "type": "string",
      "title": "Index",
      "description": "Index to Insert Document Into",
      "order": 1
    },
    "_source": {
      "type": "string",
      "title": "Source",
      "description": "Control If and How Source is Returned",
      "order": 10
    },
    "_type": {
      "type": "string",
      "title": "Type",
      "description": "Type of Document to Index",
      "order": 2
    },
    "_version": {
      "type": "integer",
      "title": "Version",
      "description": "Optional Version Specification",
      "order": 11
    },
    "parent": {
      "type": "string",
      "title": "Parent",
      "description": "Optional Parent",
      "order": 6
    },
    "refresh": {
      "type": "string",
      "title": "Refresh",
      "description": "Control when Changes Become Visible",
      "default": "false",
      "enum": [
        "true",
        "wait_for",
        "false"
      ],
      "order": 9
    },
    "retry_on_conflict": {
      "type": "integer",
      "title": "Retry on Conflict",
      "description": "Optional Number of Times to Retry on Update Conflict",
      "order": 4
    },
    "routing": {
      "type": "string",
      "title": "Routing",
      "description": "Optional Shard Placement",
      "order": 5
    },
    "script": {
      "type": "object",
      "title": "Script",
      "description": "JSON Script to Modify a Document",
      "order": 12
    },
    "timeout": {
      "type": "string",
      "title": "Timeout",
      "description": "Custom Timeout Window",
      "default": "1m",
      "order": 7
    },
    "wait_for_active_shards": {
      "type": "integer",
      "title": "Wait for Active Shards",
      "description": "Number of Shard Copies required Before Update",
      "order": 8
    }
  },
  "required": [
    "_id",
    "_index",
    "script"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class UpdateDocumentOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "update_response": {
      "$ref": "#/definitions/op_response",
      "title": "Result of Update Operation",
      "description": "Updated response",
      "order": 1
    }
  },
  "definitions": {
    "_shards": {
      "type": "object",
      "title": "_shards",
      "properties": {
        "failed": {
          "type": "integer",
          "title": "Failed",
          "description": "Number of Failed Shards",
          "order": 3
        },
        "skipped": {
          "type": "integer",
          "title": "Skipped",
          "description": "Number of Skipped Shards",
          "order": 4
        },
        "successful": {
          "type": "integer",
          "title": "Successful",
          "description": "Number of Successful Shards",
          "order": 2
        },
        "total": {
          "type": "integer",
          "title": "Total",
          "description": "Number of Total Shards",
          "order": 1
        }
      }
    },
    "op_response": {
      "type": "object",
      "title": "op_response",
      "properties": {
        "_id": {
          "type": "string",
          "title": "ID",
          "description": "Document ID",
          "order": 3
        },
        "_index": {
          "type": "string",
          "title": "Index",
          "description": "Document Index",
          "order": 1
        },
        "_shards": {
          "$ref": "#/definitions/_shards",
          "title": "Shards",
          "description": "Information About the Replication Process",
          "order": 6
        },
        "_type": {
          "type": "string",
          "title": "Type",
          "description": "Document Type",
          "order": 2
        },
        "_version": {
          "type": "integer",
          "title": "Version",
          "description": "Document Version",
          "order": 4
        },
        "created": {
          "type": "boolean",
          "title": "Created",
          "description": "Flag for Successful Creation",
          "order": 7
        },
        "result": {
          "type": "string",
          "title": "Result",
          "description": "Result of Index",
          "order": 5
        }
      },
      "definitions": {
        "_shards": {
          "type": "object",
          "title": "_shards",
          "properties": {
            "failed": {
              "type": "integer",
              "title": "Failed",
              "description": "Number of Failed Shards",
              "order": 3
            },
            "skipped": {
              "type": "integer",
              "title": "Skipped",
              "description": "Number of Skipped Shards",
              "order": 4
            },
            "successful": {
              "type": "integer",
              "title": "Successful",
              "description": "Number of Successful Shards",
              "order": 2
            },
            "total": {
              "type": "integer",
              "title": "Total",
              "description": "Number of Total Shards",
              "order": 1
            }
          }
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
