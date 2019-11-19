# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Lookup IP address"


class Input:
    ADDRESS = "address"
    

class Output:
    ADDRESS_RECORD = "address_record"
    FOUND = "found"
    

class LookupAddressInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "address": {
      "type": "string",
      "title": "Address",
      "description": "IP Address, e.g. 4.2.2.2",
      "order": 1
    }
  },
  "required": [
    "address"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class LookupAddressOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "address_record": {
      "$ref": "#/definitions/address_record",
      "title": "Address Record",
      "description": "IP Address Record",
      "order": 1
    },
    "found": {
      "type": "boolean",
      "title": "Found",
      "description": "True if found",
      "order": 2
    }
  },
  "definitions": {
    "address_record": {
      "type": "object",
      "title": "address_record",
      "properties": {
        "autonomous_system_name": {
          "type": "string",
          "title": "Autonomous System Name",
          "description": "Autonomous System Name",
          "order": 2
        },
        "autonomous_system_number": {
          "type": "string",
          "title": "Autonomous System Number",
          "order": 8
        },
        "country": {
          "type": "string",
          "title": "Country",
          "description": "Country Code",
          "order": 3
        },
        "ever_compromised": {
          "type": "boolean",
          "title": "Ever Compromised",
          "description": "True if ever compromised",
          "order": 4
        },
        "latitude": {
          "type": "number",
          "title": "Latitude",
          "order": 6
        },
        "longitude": {
          "type": "number",
          "title": "Longitude",
          "order": 7
        },
        "network": {
          "type": "string",
          "title": "Network",
          "description": "Network subnet",
          "order": 1
        },
        "sinkhole": {
          "type": "boolean",
          "title": "Sinkhole",
          "description": "True if sinkholed",
          "order": 5
        },
        "tags": {
          "type": "array",
          "title": "Tags",
          "description": "Tags",
          "items": {
            "type": "string"
          },
          "order": 9
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
