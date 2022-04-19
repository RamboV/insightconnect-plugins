# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Create a new user account (limited to external authentication sources)"


class Input:
    ACCESS_ALL_ASSET_GROUPS = "access_all_asset_groups"
    ACCESS_ALL_SITES = "access_all_sites"
    AUTHENTICATION_ID = "authentication_id"
    AUTHENTICATION_TYPE = "authentication_type"
    EMAIL = "email"
    ENABLED = "enabled"
    LOGIN = "login"
    NAME = "name"
    ROLE_ID = "role_id"
    

class Output:
    ID = "id"
    LINKS = "links"
    

class CreateUserInput(insightconnect_plugin_runtime.Input):
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
      "order": 7
    },
    "access_all_sites": {
      "type": "boolean",
      "title": "Access All Sites",
      "description": "Whether to grant the user access to all sites",
      "default": false,
      "order": 8
    },
    "authentication_id": {
      "type": "integer",
      "title": "Authentication ID",
      "description": "The identifier of the authentication source to use to authenticate the user. The source with the specified identifier must be of the type specified by Authentication Type. If Authentication ID is omitted, then one source of the specified Authentication Type is selected",
      "order": 1
    },
    "authentication_type": {
      "type": "string",
      "title": "Authentication Type",
      "description": "The type of the authentication source to use to authenticate the user",
      "default": "ldap",
      "enum": [
        "kerberos",
        "ldap",
        "saml"
      ],
      "order": 2
    },
    "email": {
      "type": "string",
      "title": "Email",
      "description": "The email address of the user",
      "order": 3
    },
    "enabled": {
      "type": "boolean",
      "title": "Enabled",
      "description": "Whether the user account is enabled",
      "default": true,
      "order": 4
    },
    "login": {
      "type": "string",
      "title": "Login",
      "description": "The login name of the user",
      "order": 5
    },
    "name": {
      "type": "string",
      "title": "Name",
      "description": "The full name of the user",
      "order": 6
    },
    "role_id": {
      "type": "string",
      "title": "Role ID",
      "description": "The identifier of the role to which the user should be assigned, e.g 'global-admin'",
      "order": 9
    }
  },
  "required": [
    "access_all_asset_groups",
    "access_all_sites",
    "authentication_type",
    "email",
    "enabled",
    "login",
    "name",
    "role_id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class CreateUserOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "id": {
      "type": "integer",
      "title": "ID",
      "description": "The identifier of the created user account",
      "order": 2
    },
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
    "id",
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
