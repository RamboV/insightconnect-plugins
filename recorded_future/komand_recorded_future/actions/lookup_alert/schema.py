# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Get information about an Alert"


class Input:
    ALERT_ID = "alert_id"
    

class Output:
    ALERT = "alert"
    

class LookupAlertInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "alert_id": {
      "type": "string",
      "title": "Alert ID",
      "description": "Alert ID",
      "order": 1
    }
  },
  "required": [
    "alert_id"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class LookupAlertOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "alert": {
      "$ref": "#/definitions/alert",
      "title": "Alert",
      "description": "Alert Details",
      "order": 1
    }
  },
  "required": [
    "alert"
  ],
  "definitions": {
    "alert": {
      "type": "object",
      "title": "alert",
      "properties": {
        "counts": {
          "$ref": "#/definitions/counts",
          "title": "Counts",
          "order": 1
        },
        "entities": {
          "type": "array",
          "title": "Entities",
          "items": {
            "$ref": "#/definitions/entities"
          },
          "order": 2
        },
        "id": {
          "type": "string",
          "title": "Id",
          "order": 3
        },
        "review": {
          "$ref": "#/definitions/review",
          "title": "Review",
          "order": 4
        },
        "rule": {
          "$ref": "#/definitions/rule",
          "title": "Rule",
          "order": 5
        },
        "title": {
          "type": "string",
          "title": "Title",
          "order": 6
        },
        "triggered": {
          "type": "string",
          "title": "Triggered",
          "order": 7
        },
        "type": {
          "type": "string",
          "title": "Type",
          "order": 8
        },
        "url": {
          "type": "string",
          "title": "Url",
          "order": 9
        }
      },
      "definitions": {
        "counts": {
          "type": "object",
          "title": "counts",
          "properties": {
            "count": {
              "type": "integer",
              "title": "Count",
              "order": 1
            },
            "date": {
              "type": "string",
              "title": "Date",
              "order": 2
            }
          }
        },
        "entities": {
          "type": "object",
          "title": "entities",
          "properties": {
            "count": {
              "type": "integer",
              "title": "Count",
              "order": 1
            },
            "entity": {
              "$ref": "#/definitions/entity",
              "title": "Entity",
              "order": 2
            }
          },
          "definitions": {
            "entity": {
              "type": "object",
              "title": "entity",
              "properties": {
                "description": {
                  "type": "string",
                  "title": "Description",
                  "order": 4
                },
                "id": {
                  "type": "string",
                  "title": "Id",
                  "order": 1
                },
                "name": {
                  "type": "string",
                  "title": "Name",
                  "order": 2
                },
                "type": {
                  "type": "string",
                  "title": "Type",
                  "order": 3
                }
              }
            }
          }
        },
        "entity": {
          "type": "object",
          "title": "entity",
          "properties": {
            "description": {
              "type": "string",
              "title": "Description",
              "order": 4
            },
            "id": {
              "type": "string",
              "title": "Id",
              "order": 1
            },
            "name": {
              "type": "string",
              "title": "Name",
              "order": 2
            },
            "type": {
              "type": "string",
              "title": "Type",
              "order": 3
            }
          }
        },
        "review": {
          "type": "object",
          "title": "review",
          "properties": {
            "status": {
              "type": "string",
              "title": "Status",
              "order": 1
            }
          }
        },
        "rule": {
          "type": "object",
          "title": "rule",
          "properties": {
            "id": {
              "type": "string",
              "title": "Id",
              "order": 1
            },
            "name": {
              "type": "string",
              "title": "Name",
              "order": 2
            },
            "url": {
              "type": "string",
              "title": "Url",
              "order": 3
            }
          }
        }
      }
    },
    "counts": {
      "type": "object",
      "title": "counts",
      "properties": {
        "count": {
          "type": "integer",
          "title": "Count",
          "order": 1
        },
        "date": {
          "type": "string",
          "title": "Date",
          "order": 2
        }
      }
    },
    "entities": {
      "type": "object",
      "title": "entities",
      "properties": {
        "count": {
          "type": "integer",
          "title": "Count",
          "order": 1
        },
        "entity": {
          "$ref": "#/definitions/entity",
          "title": "Entity",
          "order": 2
        }
      },
      "definitions": {
        "entity": {
          "type": "object",
          "title": "entity",
          "properties": {
            "description": {
              "type": "string",
              "title": "Description",
              "order": 4
            },
            "id": {
              "type": "string",
              "title": "Id",
              "order": 1
            },
            "name": {
              "type": "string",
              "title": "Name",
              "order": 2
            },
            "type": {
              "type": "string",
              "title": "Type",
              "order": 3
            }
          }
        }
      }
    },
    "entity": {
      "type": "object",
      "title": "entity",
      "properties": {
        "description": {
          "type": "string",
          "title": "Description",
          "order": 4
        },
        "id": {
          "type": "string",
          "title": "Id",
          "order": 1
        },
        "name": {
          "type": "string",
          "title": "Name",
          "order": 2
        },
        "type": {
          "type": "string",
          "title": "Type",
          "order": 3
        }
      }
    },
    "review": {
      "type": "object",
      "title": "review",
      "properties": {
        "status": {
          "type": "string",
          "title": "Status",
          "order": 1
        }
      }
    },
    "rule": {
      "type": "object",
      "title": "rule",
      "properties": {
        "id": {
          "type": "string",
          "title": "Id",
          "order": 1
        },
        "name": {
          "type": "string",
          "title": "Name",
          "order": 2
        },
        "url": {
          "type": "string",
          "title": "Url",
          "order": 3
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
