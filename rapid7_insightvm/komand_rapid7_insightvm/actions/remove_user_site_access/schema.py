# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Remove site access from an user account"


class Input:
    SITE_ID = "site_id"
    USER_ID = "user_id"
    

class Output:
    LINKS = "links"
    

class RemoveUserSiteAccessInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "site_id": {
      "type": "integer",
      "title": "Site ID",
      "description": "The identifier of the site",
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
    "site_id",
    "user_id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class RemoveUserSiteAccessOutput(komand.Output):
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
