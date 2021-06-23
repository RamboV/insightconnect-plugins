# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Grant a user account access to an asset group by ID"


class Input:
    ASSET_GROUP_ID = "asset_group_id"
    USER_ID = "user_id"
    

class Output:
    LINKS = "links"
    

class AddUserAssetGroupAccessInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "asset_group_id": {
      "type": "integer",
      "title": "Asset Group ID",
      "description": "The identifier of the asset group",
      "order": 2
    },
    "user_id": {
      "type": "integer",
      "title": "User ID",
      "description": "The identifier of the user account",
      "order": 1
    }
  },
  "required": [
    "asset_group_id",
    "user_id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class AddUserAssetGroupAccessOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "links": {
      "type": "array",
      "title": "Links",
      "description": "Hypermedia links to corresponding or related resources",
      "items": {
        "$ref": "#/definitions/link"
      },
      "order": 1
    }
  },
  "required": [
    "links"
  ],
  "definitions": {
    "link": {
      "type": "object",
      "title": "link",
      "properties": {
        "href": {
          "type": "string",
          "title": "URL",
          "description": "A hypertext reference, which is either a URI (see RFC 3986) or URI template (see RFC 6570)",
          "order": 1
        },
        "rel": {
          "type": "string",
          "title": "Rel",
          "description": "Link relation type following RFC 5988",
          "order": 2
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
