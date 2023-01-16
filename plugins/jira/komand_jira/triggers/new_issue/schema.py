# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Trigger which indicates that a new issue has been created"


class Input:
    
    GET_ATTACHMENTS = "get_attachments"
    INCLUDE_FIELDS = "include_fields"
    JQL = "jql"
    POLL_TIMEOUT = "poll_timeout"
    PROJECT = "project"
    

class Output:
    
    ISSUE = "issue"
    

class NewIssueInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "get_attachments": {
      "type": "boolean",
      "title": "Get Attachments",
      "description": "Get attachments from issue",
      "default": false,
      "order": 3
    },
    "include_fields": {
      "type": "boolean",
      "title": "Include Fields",
      "description": "Whether returned Issues should include fields",
      "default": false,
      "order": 5
    },
    "jql": {
      "type": "string",
      "title": "JQL",
      "description": "JQL search string to use",
      "order": 2
    },
    "poll_timeout": {
      "type": "integer",
      "title": "Poll Timeout",
      "description": "Timeout between next poll, default 60",
      "default": 60,
      "order": 4
    },
    "project": {
      "type": "string",
      "title": "Project",
      "description": "Project ID or name",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class NewIssueOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "issue": {
      "$ref": "#/definitions/issue",
      "title": "Issue",
      "description": "New issue",
      "order": 1
    }
  },
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
    },
    "issue": {
      "type": "object",
      "title": "issue",
      "properties": {
        "assignee": {
          "type": "string",
          "title": "Assignee",
          "description": "Assigned User",
          "order": 11
        },
        "attachments": {
          "type": "array",
          "title": "Attachments",
          "description": "Attachments",
          "items": {
            "$ref": "#/definitions/file"
          },
          "order": 15
        },
        "created_at": {
          "type": "string",
          "title": "Created At",
          "description": "Created At",
          "order": 12
        },
        "description": {
          "type": "string",
          "title": "Description",
          "description": "Description",
          "order": 7
        },
        "fields": {
          "type": "object",
          "title": "Fields",
          "description": "Full list of fields",
          "order": 16
        },
        "id": {
          "type": "string",
          "title": "Id",
          "description": "Issue ID",
          "order": 1
        },
        "key": {
          "type": "string",
          "title": "Key",
          "description": "Issue Key",
          "order": 3
        },
        "labels": {
          "type": "array",
          "title": "Labels",
          "description": "Labels",
          "items": {
            "type": "string"
          },
          "order": 9
        },
        "project": {
          "type": "string",
          "title": "Project",
          "description": "Project",
          "order": 2
        },
        "reporter": {
          "type": "string",
          "title": "Reporter",
          "description": "Reporting User",
          "order": 10
        },
        "resolution": {
          "type": "string",
          "title": "Resolution",
          "description": "Resolution",
          "order": 8
        },
        "resolved_at": {
          "type": "string",
          "title": "Resolved At",
          "description": "Resolved At",
          "order": 14
        },
        "status": {
          "type": "string",
          "title": "Status",
          "description": "Status",
          "order": 4
        },
        "summary": {
          "type": "string",
          "title": "Summary",
          "description": "Summary",
          "order": 6
        },
        "updated_at": {
          "type": "string",
          "title": "Updated At",
          "description": "Updated At",
          "order": 13
        },
        "url": {
          "type": "string",
          "title": "Url",
          "description": "Issue URL",
          "order": 5
        }
      },
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
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
