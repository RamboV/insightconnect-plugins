# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Input:
    EU_CUSTOMER = "eu_customer"
    SSL_VERIFY = "ssl_verify"
    TOKEN = "token"
    

class ConnectionSchema(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "eu_customer": {
      "type": "boolean",
      "title": "EU Customer",
      "description": "Is the customer based in Europe?",
      "default": false,
      "order": 2
    },
    "ssl_verify": {
      "type": "boolean",
      "title": "SSL Verify",
      "description": "Boolean property used to decide whether to verify a TSL or SSL certificate",
      "default": true,
      "order": 3
    },
    "token": {
      "$ref": "#/definitions/credential_secret_key",
      "title": "Token",
      "description": "API Token generated by Solarwinds admin",
      "order": 1
    }
  },
  "required": [
    "eu_customer",
    "ssl_verify",
    "token"
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
