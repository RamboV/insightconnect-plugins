# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Add Host as a network object"


class Input:
    DISCARD_OTHER_SESSIONS = "discard_other_sessions"
    HOST_IP = "host_ip"
    NAME = "name"
    

class Output:
    HOST_OBJECT = "host_object"
    

class AddHostInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "discard_other_sessions": {
      "type": "boolean",
      "title": "Discard Other Sessions",
      "description": "Discard all other user sessions. This can fix errors when objects are locked by other sessions",
      "default": true,
      "order": 3
    },
    "host_ip": {
      "type": "string",
      "title": "Host IP",
      "description": "Host IP",
      "order": 2
    },
    "name": {
      "type": "string",
      "title": "Name",
      "description": "Name",
      "order": 1
    }
  },
  "required": [
    "discard_other_sessions",
    "host_ip",
    "name"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class AddHostOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "host_object": {
      "$ref": "#/definitions/host_object",
      "title": "Host",
      "description": "Information about the host that was added",
      "order": 1
    }
  },
  "required": [
    "host_object"
  ],
  "definitions": {
    "creation_time_type": {
      "type": "object",
      "title": "creation_time_type",
      "properties": {
        "iso-8601": {
          "type": "string",
          "title": "ISO-8601",
          "description": "ISO-8601",
          "order": 2
        },
        "posix": {
          "type": "integer",
          "title": "POSIX",
          "description": "POSIX",
          "order": 1
        }
      }
    },
    "domain": {
      "type": "object",
      "title": "domain",
      "properties": {
        "domain-type": {
          "type": "string",
          "title": "Domain-Type",
          "description": "Domain-type",
          "order": 1
        },
        "name": {
          "type": "string",
          "title": "Name",
          "description": "Name",
          "order": 2
        },
        "uid": {
          "type": "string",
          "title": "UID",
          "description": "UID",
          "order": 3
        }
      }
    },
    "host_object": {
      "type": "object",
      "title": "host_object",
      "properties": {
        "color": {
          "type": "string",
          "title": "Color",
          "description": "Color",
          "order": 4
        },
        "comments": {
          "type": "string",
          "title": "Comments",
          "description": "Comments",
          "order": 7
        },
        "domain": {
          "$ref": "#/definitions/domain",
          "title": "Domain",
          "description": "Domain",
          "order": 1
        },
        "groups": {
          "type": "array",
          "title": "Groups",
          "description": "Groups",
          "items": {
            "type": "object"
          },
          "order": 9
        },
        "icon": {
          "type": "string",
          "title": "Icon",
          "description": "Icon",
          "order": 14
        },
        "interfaces": {
          "type": "array",
          "title": "Interfaces",
          "description": "Interfaces",
          "items": {
            "type": "object"
          },
          "order": 5
        },
        "ipv4-address": {
          "type": "string",
          "title": "IPv4-Address",
          "description": "IPv4-address",
          "order": 11
        },
        "meta-info": {
          "$ref": "#/definitions/meta_info_type",
          "title": "Meta-Info",
          "description": "Meta-info",
          "order": 8
        },
        "name": {
          "type": "string",
          "title": "Name",
          "description": "Name",
          "order": 2
        },
        "nat-settings": {
          "type": "object",
          "title": "NAT-Settings",
          "description": "NAT-settings",
          "order": 6
        },
        "read-only": {
          "type": "boolean",
          "title": "Read-Only",
          "description": "Read-only",
          "order": 13
        },
        "tags": {
          "type": "array",
          "title": "Tags",
          "description": "Tags",
          "items": {
            "type": "object"
          },
          "order": 3
        },
        "type": {
          "type": "string",
          "title": "Type",
          "description": "Type",
          "order": 12
        },
        "uid": {
          "type": "string",
          "title": "UID",
          "description": "UID",
          "order": 10
        }
      },
      "definitions": {
        "creation_time_type": {
          "type": "object",
          "title": "creation_time_type",
          "properties": {
            "iso-8601": {
              "type": "string",
              "title": "ISO-8601",
              "description": "ISO-8601",
              "order": 2
            },
            "posix": {
              "type": "integer",
              "title": "POSIX",
              "description": "POSIX",
              "order": 1
            }
          }
        },
        "domain": {
          "type": "object",
          "title": "domain",
          "properties": {
            "domain-type": {
              "type": "string",
              "title": "Domain-Type",
              "description": "Domain-type",
              "order": 1
            },
            "name": {
              "type": "string",
              "title": "Name",
              "description": "Name",
              "order": 2
            },
            "uid": {
              "type": "string",
              "title": "UID",
              "description": "UID",
              "order": 3
            }
          }
        },
        "meta_info_type": {
          "type": "object",
          "title": "meta_info_type",
          "properties": {
            "creation-time": {
              "$ref": "#/definitions/creation_time_type",
              "title": "Creation-Time",
              "description": "Creation-time",
              "order": 2
            },
            "creator": {
              "type": "string",
              "title": "Creator",
              "description": "Creator",
              "order": 6
            },
            "last-modifier": {
              "type": "string",
              "title": "Last-Modifier",
              "description": "Last-modifier",
              "order": 3
            },
            "last-modify-time": {
              "$ref": "#/definitions/creation_time_type",
              "title": "Last-Modify-Time",
              "description": "Last-modify-time",
              "order": 4
            },
            "lock": {
              "type": "string",
              "title": "Lock",
              "description": "Lock",
              "order": 5
            },
            "validation-state": {
              "type": "string",
              "title": "Validation-State",
              "description": "Validation-state",
              "order": 1
            }
          },
          "definitions": {
            "creation_time_type": {
              "type": "object",
              "title": "creation_time_type",
              "properties": {
                "iso-8601": {
                  "type": "string",
                  "title": "ISO-8601",
                  "description": "ISO-8601",
                  "order": 2
                },
                "posix": {
                  "type": "integer",
                  "title": "POSIX",
                  "description": "POSIX",
                  "order": 1
                }
              }
            }
          }
        }
      }
    },
    "meta_info_type": {
      "type": "object",
      "title": "meta_info_type",
      "properties": {
        "creation-time": {
          "$ref": "#/definitions/creation_time_type",
          "title": "Creation-Time",
          "description": "Creation-time",
          "order": 2
        },
        "creator": {
          "type": "string",
          "title": "Creator",
          "description": "Creator",
          "order": 6
        },
        "last-modifier": {
          "type": "string",
          "title": "Last-Modifier",
          "description": "Last-modifier",
          "order": 3
        },
        "last-modify-time": {
          "$ref": "#/definitions/creation_time_type",
          "title": "Last-Modify-Time",
          "description": "Last-modify-time",
          "order": 4
        },
        "lock": {
          "type": "string",
          "title": "Lock",
          "description": "Lock",
          "order": 5
        },
        "validation-state": {
          "type": "string",
          "title": "Validation-State",
          "description": "Validation-state",
          "order": 1
        }
      },
      "definitions": {
        "creation_time_type": {
          "type": "object",
          "title": "creation_time_type",
          "properties": {
            "iso-8601": {
              "type": "string",
              "title": "ISO-8601",
              "description": "ISO-8601",
              "order": 2
            },
            "posix": {
              "type": "integer",
              "title": "POSIX",
              "description": "POSIX",
              "order": 1
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
