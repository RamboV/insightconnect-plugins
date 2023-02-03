# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Update the configuration of an existing user account"


class Input:
    ACCESS_ALL_ASSET_GROUPS = "access_all_asset_groups"
    ACCESS_ALL_SITES = "access_all_sites"
    AUTHENTICATION_ID = "authentication_id"
    AUTHENTICATION_TYPE = "authentication_type"
    EMAIL = "email"
    ENABLED = "enabled"
    ID = "id"
    LOGIN = "login"
    NAME = "name"
    ROLE_ID = "role_id"
    

class Output:
    LINKS = "links"
    

class UpdateUserInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "access_all_asset_groups": {
      "type": "boolean",
      "title": "Access All Asset Groups",
      "description": "Whether to grant the user access to all asset groups",
      "default": false,
      "order": 8
    },
    "access_all_sites": {
      "type": "boolean",
      "title": "Access All Sites",
      "description": "Whether to grant the user access to all sites",
      "default": false,
      "order": 9
    },
    "authentication_id": {
      "type": "integer",
      "title": "Authentication ID",
      "description": "The identifier of the authentication source to use to authenticate the user. The source with the specified identifier must be of the type specified by Authentication Type. If Authentication ID is omitted, then one source of the specified Authentication Type is selected",
      "order": 2
    },
    "authentication_type": {
      "type": "string",
      "title": "Authentication Type",
      "description": "The type of the authentication source to use to authenticate the user",
      "default": "ldap",
      "enum": [
        "normal",
        "admin",
        "kerberos",
        "ldap",
        "saml"
      ],
      "order": 3
    },
    "email": {
      "type": "string",
      "title": "Email",
      "description": "The email address of the user",
      "order": 4
    },
    "enabled": {
      "type": "boolean",
      "title": "Enabled",
      "description": "Whether the user account is enabled",
      "default": true,
      "order": 5
    },
    "id": {
      "type": "integer",
      "title": "ID",
      "description": "The identifier of the user",
      "order": 1
    },
    "login": {
      "type": "string",
      "title": "Login",
      "description": "The login name of the user",
      "order": 6
    },
    "name": {
      "type": "string",
      "title": "Name",
      "description": "The full name of the user",
      "order": 7
    },
    "role_id": {
      "type": "string",
      "title": "Role ID",
      "description": "The identifier of the role to which the user should be assigned",
      "order": 10
    }
  },
  "required": [
    "access_all_asset_groups",
    "access_all_sites",
    "authentication_type",
    "email",
    "enabled",
    "id",
    "login",
    "name",
    "role_id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class UpdateUserOutput(insightconnect_plugin_runtime.Output):
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
