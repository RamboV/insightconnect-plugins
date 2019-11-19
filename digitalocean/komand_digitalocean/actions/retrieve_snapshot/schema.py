# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Retrieves an existing snapshot from an account"


class Input:
    SNAPSHOT_ID = "snapshot_id"
    

class Output:
    SNAPSHOT = "snapshot"
    

class RetrieveSnapshotInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "snapshot_id": {
      "type": "string",
      "title": "Snapshot ID",
      "description": "ID of snapshot to retrieve",
      "order": 1
    }
  },
  "required": [
    "snapshot_id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class RetrieveSnapshotOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "snapshot": {
      "$ref": "#/definitions/snapshot",
      "title": "Snapshot",
      "description": "Snapshot from the account",
      "order": 1
    }
  },
  "definitions": {
    "snapshot": {
      "type": "object",
      "title": "snapshot",
      "properties": {
        "created_at": {
          "type": "string",
          "title": "Created At",
          "order": 3
        },
        "id": {
          "type": "string",
          "title": "Id",
          "order": 1
        },
        "min_disk_size": {
          "type": "number",
          "title": "Min Disk Size",
          "order": 7
        },
        "name": {
          "type": "string",
          "title": "Name",
          "order": 2
        },
        "regions": {
          "type": "array",
          "title": "Regions",
          "items": {
            "type": "string"
          },
          "order": 4
        },
        "resource_id": {
          "type": "string",
          "title": "Resource Id",
          "order": 5
        },
        "resource_type": {
          "type": "string",
          "title": "Resource Type",
          "order": 6
        },
        "size_gigabytes": {
          "type": "number",
          "title": "Size Gigabytes",
          "order": 8
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
