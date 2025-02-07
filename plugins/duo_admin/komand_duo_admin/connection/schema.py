# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Input:
    HOSTNAME = "hostname"
    INTEGRATIONKEY = "integrationKey"
    SECRETKEY = "secretKey"
    

class ConnectionSchema(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "hostname": {
      "type": "string",
      "title": "API Hostname",
      "description": "Duo API hostname",
      "order": 3
    },
    "integrationKey": {
      "$ref": "#/definitions/credential_secret_key",
      "title": "Integration Key",
      "description": "API integration key",
      "order": 1
    },
    "secretKey": {
      "$ref": "#/definitions/credential_secret_key",
      "title": "Secret Key",
      "description": "API secret key",
      "order": 2
    }
  },
  "required": [
    "hostname",
    "integrationKey",
    "secretKey"
  ],
  "definitions": {
    "credential_secret_key": {
      "id": "credential_secret_key",
      "type": "object",
      "title": "Credential: Secret Key",
      "description": "A shared secret key",
      "properties": {
        "secretKey": {
          "type": "string",
          "title": "Secret Key",
          "displayType": "password",
          "description": "The shared secret key",
          "format": "password"
        }
      },
      "required": [
        "secretKey"
      ]
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
