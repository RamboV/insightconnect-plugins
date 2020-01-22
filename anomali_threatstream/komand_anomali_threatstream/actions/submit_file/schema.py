# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Submit a file to a ThreatStream sandbox"


class Input:
    CLASSIFICATION = "classification"
    DETAIL = "detail"
    FILE = "file"
    PLATFORM = "platform"
    USE_PREMIUM_SANDBOX = "use_premium_sandbox"
    

class Output:
    REPORTS = "reports"
    SUCCESS = "success"
    

class SubmitFileInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "classification": {
      "type": "string",
      "title": "Classification",
      "description": "Classification of the Sandbox submission, either public or private",
      "default": "private",
      "enum": [
        "private",
        "public"
      ],
      "order": 2
    },
    "detail": {
      "type": "string",
      "title": "Detail",
      "description": "A comma-separated list that provides additional details for the indicator. This information is displayed in the Tag column of the ThreatStream UI. For example, \\"Credential-Exposure,compromised_email\\"",
      "order": 5
    },
    "file": {
      "$ref": "#/definitions/file",
      "title": "File",
      "description": "File to detonate",
      "order": 4
    },
    "platform": {
      "type": "string",
      "title": "Platform",
      "description": "Platform on which the submitted URL or file will be run",
      "enum": [
        "ALL",
        "ANDROID4.4",
        "ANDROID5.1",
        "ANDROID6.0",
        "MACOSX",
        "WINDOWSXP",
        "WINDOWSXPNATIVE",
        "WINDOWS7",
        "WINDOWS7NATIVE",
        "WINDOWS7OFFICE2010",
        "WINDOWS7OFFICE2013",
        "WINDOWS10",
        "WINDOWS10x64"
      ],
      "order": 1
    },
    "use_premium_sandbox": {
      "type": "boolean",
      "title": "Use Premium Sandbox",
      "description": "Specify whether the premium sandbox should be used for detonation",
      "order": 3
    }
  },
  "required": [
    "file",
    "platform",
    "use_premium_sandbox"
  ],
  "definitions": {
    "file": {
      "id": "file",
      "type": "object",
      "title": "File",
      "description": "File Object",
      "properties": {
        "content": {
          "type": "string",
          "title": "Content",
          "description": "File contents",
          "format": "bytes"
        },
        "filename": {
          "type": "string",
          "title": "Filename",
          "description": "Name of file"
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class SubmitFileOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "reports": {
      "type": "array",
      "title": "Reports",
      "description": "Reports containing submission details",
      "items": {
        "$ref": "#/definitions/report"
      },
      "order": 2
    },
    "success": {
      "type": "boolean",
      "title": "Success",
      "description": "Operation status",
      "order": 1
    }
  },
  "definitions": {
    "report": {
      "type": "object",
      "title": "report",
      "properties": {
        "detail": {
          "type": "string",
          "title": "Details",
          "order": 2
        },
        "id": {
          "type": "integer",
          "title": "ID",
          "description": "Submission ID",
          "order": 3
        },
        "platform": {
          "type": "string",
          "title": "Platform",
          "description": "Platform on which the submitted URL or file will be run",
          "order": 4
        },
        "status": {
          "type": "string",
          "title": "Status",
          "order": 1
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
