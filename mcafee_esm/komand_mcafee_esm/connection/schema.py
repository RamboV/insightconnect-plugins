# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Input:
    CREDENTIALS = "credentials"
    HOSTNAME = "hostname"
    PORT = "port"
    

class ConnectionSchema(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "credentials": {
      "$ref": "#/definitions/credential_username_password",
      "title": "Credentials",
      "description": "Username and password for McAfee ESM",
      "order": 1
    },
    "hostname": {
      "type": "string",
      "title": "Hostname",
      "description": "Hostname to  McAfee ESM Server",
      "order": 2
    },
    "port": {
      "type": "string",
      "title": "Port",
      "description": "McAfee ESM host port",
      "default": "443",
      "order": 3
    }
  },
  "required": [
    "credentials",
    "hostname",
    "port"
  ],
  "definitions": {
    "credential_username_password": {
      "id": "credential_username_password",
      "type": "object",
      "title": "Credential: Username and Password",
      "description": "A username and password combination",
      "properties": {
        "password": {
          "type": "string",
          "title": "Password",
          "displayType": "password",
          "description": "The password",
          "format": "password"
        },
        "username": {
          "type": "string",
          "title": "Username",
          "description": "The username to log in with"
        }
      },
      "required": [
        "username",
        "password"
      ]
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
