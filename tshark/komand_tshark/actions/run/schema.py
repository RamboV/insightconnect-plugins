# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Run Tshark on a PCAP"


class Input:
    FILE = "file"
    FILTER = "filter"
    OPTIONS = "options"
    

class Output:
    DUMP_CONTENTS = "dump_contents"
    DUMP_FILE = "dump_file"
    

class RunInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "file": {
      "type": "string",
      "title": "Base64 Encoded PCAP",
      "displayType": "bytes",
      "description": "Base64 encoded PCAP",
      "format": "bytes",
      "order": 1
    },
    "filter": {
      "type": "string",
      "title": "Display Filter",
      "description": "Display filter E.g. tcp.port eq 80",
      "default": "ip or ipv6",
      "order": 3
    },
    "options": {
      "type": "string",
      "title": "Options",
      "description": "Tshark flags and options E.g. -n -c 10 -s 96. -r is implied",
      "order": 2
    }
  },
  "required": [
    "file"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class RunOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "dump_contents": {
      "type": "array",
      "title": "Traffic Dump",
      "description": "Traffic dump as array",
      "items": {
        "type": "string"
      },
      "order": 2
    },
    "dump_file": {
      "type": "string",
      "title": "Traffic File",
      "displayType": "bytes",
      "description": "Traffic dump file",
      "format": "bytes",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
