# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "List all feeds"


class Input:
    pass

class Output:
    FEEDS = "feeds"
    

class ListFeedsInput(komand.Input):
    schema = json.loads("""
   {}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class ListFeedsOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "feeds": {
      "type": "array",
      "title": "Feeds",
      "description": "The list of feeds",
      "items": {
        "$ref": "#/definitions/feed"
      },
      "order": 1
    }
  },
  "definitions": {
    "feed": {
      "type": "object",
      "title": "feed",
      "properties": {
        "category": {
          "type": "string",
          "title": "Category",
          "order": 7
        },
        "display_name": {
          "type": "string",
          "title": "Display Name",
          "order": 8
        },
        "enabled": {
          "type": "boolean",
          "title": "Enabled",
          "order": 21
        },
        "feed_url": {
          "type": "string",
          "title": "Feed URL",
          "order": 10
        },
        "icon": {
          "type": "string",
          "title": "Icon",
          "displayType": "bytes",
          "format": "bytes",
          "order": 16
        },
        "icon_small": {
          "type": "string",
          "title": "Icon Small",
          "displayType": "bytes",
          "format": "bytes",
          "order": 5
        },
        "id": {
          "type": "integer",
          "title": "ID",
          "order": 6
        },
        "local_rating": {
          "type": "integer",
          "title": "Local Rating",
          "order": 3
        },
        "manually_added": {
          "type": "boolean",
          "title": "Manually Added",
          "order": 14
        },
        "name": {
          "type": "string",
          "title": "Name",
          "order": 18
        },
        "order": {
          "type": "integer",
          "title": "Order",
          "order": 24
        },
        "password": {
          "type": "string",
          "title": "Password",
          "order": 15
        },
        "provider_rating": {
          "type": "number",
          "title": "Provider Rating",
          "order": 17
        },
        "provider_url": {
          "type": "string",
          "title": "Provider URL",
          "order": 1
        },
        "requires": {
          "type": "string",
          "title": "Requires",
          "order": 20
        },
        "requires_what": {
          "type": "string",
          "title": "Requires What",
          "order": 23
        },
        "requires_who": {
          "type": "string",
          "title": "Requires Who",
          "order": 4
        },
        "ssl_client_crt": {
          "type": "string",
          "title": "SSL Client Certificate",
          "order": 2
        },
        "ssl_client_key": {
          "type": "string",
          "title": "SSL Client Key",
          "order": 13
        },
        "summary": {
          "type": "string",
          "title": "Summary",
          "order": 22
        },
        "tech_data": {
          "type": "string",
          "title": "Tech Data",
          "order": 19
        },
        "use_proxy": {
          "type": "boolean",
          "title": "Use Proxy",
          "order": 9
        },
        "username": {
          "type": "string",
          "title": "Username",
          "order": 11
        },
        "validate_server_cert": {
          "type": "boolean",
          "title": "Validate Server Cert",
          "order": 12
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
