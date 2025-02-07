# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Get a list of incidents identified by Armorblox. By default, it starts querying for all the incidents since the previous day"


class Input:
    
    INTERVAL = "interval"
    

class Output:
    
    INCIDENTS = "incidents"
    

class GetIncidentsInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "interval": {
      "type": "integer",
      "title": "Fetch Interval",
      "description": "Polling interval in seconds",
      "default": 600,
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class GetIncidentsOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "incidents": {
      "type": "array",
      "title": "Incidents",
      "description": "A list of incidents identified by Armorblox",
      "items": {
        "$ref": "#/definitions/incident"
      },
      "order": 1
    }
  },
  "required": [
    "incidents"
  ],
  "definitions": {
    "engagement": {
      "type": "object",
      "title": "engagement",
      "properties": {
        "fwd_mail_count": {
          "type": "string",
          "title": "Forwarded Mail Count",
          "description": "Forwarded Mail Count",
          "order": 1
        },
        "reply_mail_count": {
          "type": "string",
          "title": "Reply Mail Count",
          "description": "Reply Mail Count",
          "order": 2
        }
      }
    },
    "final_detection_tag": {
      "type": "object",
      "title": "final_detection_tag",
      "properties": {
        "detection_tag_id": {
          "type": "string",
          "title": "Detection Tag ID",
          "description": "Detection tag ID",
          "order": 1
        },
        "detection_tag_name": {
          "type": "string",
          "title": "Detection Tag name",
          "description": "Detection tag name",
          "order": 2
        }
      }
    },
    "incident": {
      "type": "object",
      "title": "incident",
      "properties": {
        "app_name": {
          "type": "string",
          "title": "App Name",
          "description": "App Name",
          "order": 9
        },
        "date": {
          "type": "string",
          "title": "Incident Date",
          "displayType": "date",
          "description": "Date of the incident",
          "format": "date-time",
          "order": 3
        },
        "engagements": {
          "$ref": "#/definitions/engagement",
          "title": "Engagements",
          "description": "Engagements",
          "order": 14
        },
        "external_senders": {
          "type": "array",
          "title": "External Senders",
          "description": "List of external senders",
          "items": {
            "type": "string"
          },
          "order": 10
        },
        "external_users": {
          "type": "array",
          "title": "External Users",
          "description": "List of external users",
          "items": {
            "$ref": "#/definitions/user"
          },
          "order": 17
        },
        "final_detection_tags": {
          "type": "array",
          "title": "Detection Tags",
          "description": "Detection tags",
          "items": {
            "$ref": "#/definitions/final_detection_tag"
          },
          "order": 18
        },
        "folder_categories": {
          "type": "array",
          "title": "Folder Categories",
          "description": "Folder categories",
          "items": {
            "type": "string"
          },
          "order": 11
        },
        "id": {
          "type": "string",
          "title": "Incident ID",
          "description": "Incident ID",
          "order": 8
        },
        "incident_type": {
          "type": "string",
          "title": "Incident Type",
          "description": "Incident Type",
          "order": 13
        },
        "object_type": {
          "type": "string",
          "title": "Object Type",
          "description": "Type of the object",
          "order": 7
        },
        "policy_names": {
          "type": "array",
          "title": "policy Names",
          "description": "List of policies",
          "items": {
            "type": "string"
          },
          "order": 4
        },
        "priority": {
          "type": "string",
          "title": "Priority",
          "description": "Priority of the incident",
          "order": 1
        },
        "remediation_actions": {
          "type": "array",
          "title": "Remediation Action",
          "description": "Remediation Action",
          "items": {
            "type": "string"
          },
          "order": 15
        },
        "resolution_state": {
          "type": "string",
          "title": "Resolution State",
          "description": "Incident resolution state",
          "order": 6
        },
        "scl_score": {
          "type": "integer",
          "title": "SCL Score",
          "order": 12
        },
        "tagged": {
          "type": "boolean",
          "title": "Is email tagged",
          "description": "Is email tagged",
          "order": 2
        },
        "title": {
          "type": "string",
          "title": "Title",
          "description": "Mail subject",
          "order": 5
        },
        "users": {
          "type": "array",
          "title": "Users",
          "description": "List of users",
          "items": {
            "$ref": "#/definitions/user"
          },
          "order": 16
        }
      },
      "definitions": {
        "engagement": {
          "type": "object",
          "title": "engagement",
          "properties": {
            "fwd_mail_count": {
              "type": "string",
              "title": "Forwarded Mail Count",
              "description": "Forwarded Mail Count",
              "order": 1
            },
            "reply_mail_count": {
              "type": "string",
              "title": "Reply Mail Count",
              "description": "Reply Mail Count",
              "order": 2
            }
          }
        },
        "final_detection_tag": {
          "type": "object",
          "title": "final_detection_tag",
          "properties": {
            "detection_tag_id": {
              "type": "string",
              "title": "Detection Tag ID",
              "description": "Detection tag ID",
              "order": 1
            },
            "detection_tag_name": {
              "type": "string",
              "title": "Detection Tag name",
              "description": "Detection tag name",
              "order": 2
            }
          }
        },
        "user": {
          "type": "object",
          "title": "user",
          "properties": {
            "email": {
              "type": "string",
              "title": "User Email",
              "description": "Email of the user",
              "order": 2
            },
            "is_vip": {
              "type": "boolean",
              "title": "Is User VIP",
              "description": "Is User VIP",
              "order": 3
            },
            "name": {
              "type": "string",
              "title": "User Name",
              "description": "Name of the user",
              "order": 1
            }
          }
        }
      }
    },
    "user": {
      "type": "object",
      "title": "user",
      "properties": {
        "email": {
          "type": "string",
          "title": "User Email",
          "description": "Email of the user",
          "order": 2
        },
        "is_vip": {
          "type": "boolean",
          "title": "Is User VIP",
          "description": "Is User VIP",
          "order": 3
        },
        "name": {
          "type": "string",
          "title": "User Name",
          "description": "Name of the user",
          "order": 1
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
