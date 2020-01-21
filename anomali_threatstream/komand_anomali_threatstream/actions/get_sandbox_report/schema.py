# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Get a sandbox report"


class Input:
    REPORT_ID = "report_id"
    

class Output:
    SANDBOX_REPORT = "sandbox_report"
    

class GetSandboxReportInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "report_id": {
      "type": "string",
      "title": "Report ID",
      "description": "Report ID",
      "order": 1
    }
  },
  "required": [
    "report_id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class GetSandboxReportOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "sandbox_report": {
      "$ref": "#/definitions/sandbox_report",
      "title": "Sandbox Report",
      "description": "Sandbox Report",
      "order": 1
    }
  },
  "required": [
    "sandbox_report"
  ],
  "definitions": {
    "info": {
      "type": "object",
      "title": "info",
      "properties": {
        "category": {
          "type": "string",
          "title": "Category",
          "description": "Category",
          "order": 1
        },
        "confidence": {
          "type": "integer",
          "title": "Confidence",
          "description": "Confidence",
          "order": 2
        },
        "duration": {
          "type": "integer",
          "title": "Duration",
          "description": "Duration",
          "order": 8
        },
        "ended": {
          "type": "string",
          "title": "Ended",
          "description": "Ended",
          "order": 7
        },
        "is_malicious": {
          "type": "boolean",
          "title": "Is Malicious",
          "description": "Is malicious",
          "order": 5
        },
        "is_suspicious": {
          "type": "boolean",
          "title": "Is Suspicious",
          "description": "Is suspicious",
          "order": 4
        },
        "is_unknown": {
          "type": "boolean",
          "title": "Is Unknown",
          "description": "Is unknown",
          "order": 3
        },
        "started": {
          "type": "string",
          "title": "Started",
          "description": "Started",
          "order": 6
        }
      },
      "required": [
        "category",
        "confidence",
        "duration",
        "ended",
        "is_malicious",
        "is_suspicious",
        "is_unknown",
        "started"
      ]
    },
    "sandbox_report": {
      "type": "object",
      "title": "sandbox_report",
      "properties": {
        "domains": {
          "type": "array",
          "title": "Domains",
          "description": "Domains",
          "items": {
            "type": "string"
          },
          "order": 4
        },
        "info": {
          "$ref": "#/definitions/info",
          "title": "Info",
          "description": "Info",
          "order": 2
        },
        "screenshots": {
          "type": "array",
          "title": "Screenshots",
          "description": "Screenshots",
          "items": {
            "type": "string"
          },
          "order": 1
        },
        "signatures": {
          "type": "array",
          "title": "Signatures",
          "description": "Signatures",
          "items": {
            "type": "object"
          },
          "order": 3
        }
      },
      "required": [
        "domains",
        "info",
        "screenshots",
        "signatures"
      ],
      "definitions": {
        "info": {
          "type": "object",
          "title": "info",
          "properties": {
            "category": {
              "type": "string",
              "title": "Category",
              "description": "Category",
              "order": 1
            },
            "confidence": {
              "type": "integer",
              "title": "Confidence",
              "description": "Confidence",
              "order": 2
            },
            "duration": {
              "type": "integer",
              "title": "Duration",
              "description": "Duration",
              "order": 8
            },
            "ended": {
              "type": "string",
              "title": "Ended",
              "description": "Ended",
              "order": 7
            },
            "is_malicious": {
              "type": "boolean",
              "title": "Is Malicious",
              "description": "Is malicious",
              "order": 5
            },
            "is_suspicious": {
              "type": "boolean",
              "title": "Is Suspicious",
              "description": "Is suspicious",
              "order": 4
            },
            "is_unknown": {
              "type": "boolean",
              "title": "Is Unknown",
              "description": "Is unknown",
              "order": 3
            },
            "started": {
              "type": "string",
              "title": "Started",
              "description": "Started",
              "order": 6
            }
          },
          "required": [
            "category",
            "confidence",
            "duration",
            "ended",
            "is_malicious",
            "is_suspicious",
            "is_unknown",
            "started"
          ]
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
