# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Add an external dynamic list"


class Input:
    DAY = "day"
    DESCRIPTION = "description"
    LIST_TYPE = "list_type"
    NAME = "name"
    REPEAT = "repeat"
    SOURCE = "source"
    TIME = "time"
    

class Output:
    CODE = "code"
    MESSAGE = "message"
    STATUS = "status"
    

class AddExternalDynamicListInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "day": {
      "type": "string",
      "title": "Day",
      "description": "If repeat is weekly, choose a day to update",
      "default": "",
      "enum": [
        "",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday"
      ],
      "order": 7
    },
    "description": {
      "type": "string",
      "title": "Description",
      "description": "A description of the list",
      "order": 3
    },
    "list_type": {
      "type": "string",
      "title": "List Type",
      "description": "The type of list",
      "enum": [
        "IP List",
        "Domain List",
        "URL List"
      ],
      "order": 2
    },
    "name": {
      "type": "string",
      "title": "The Name of the List",
      "description": "An arbitrary name for the list. This name will be used to identify the list in PAN-OS",
      "order": 1
    },
    "repeat": {
      "type": "string",
      "title": "Repeat",
      "description": "The interval at which to retrieve updates from the list",
      "enum": [
        "Five Minute",
        "Hourly",
        "Daily",
        "Weekly"
      ],
      "order": 5
    },
    "source": {
      "type": "string",
      "title": "Source",
      "description": "The web site you will pull the list from e.g. http://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
      "order": 4
    },
    "time": {
      "type": "string",
      "title": "Time",
      "description": "If repeat is daily or weekly, choose an hour on a 24 hour clock to update (Default: '')",
      "default": "",
      "enum": [
        "",
        "00",
        "01",
        "02",
        "03",
        "04",
        "05",
        "06",
        "07",
        8,
        9,
        "10",
        "11",
        "12",
        "13",
        "14",
        "15",
        "16",
        "17",
        "18",
        "19",
        "20",
        "21",
        "22",
        "23"
      ],
      "order": 6
    }
  },
  "required": [
    "day",
    "description",
    "list_type",
    "name",
    "repeat",
    "source",
    "time"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class AddExternalDynamicListOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "code": {
      "type": "string",
      "title": "Code",
      "description": "Response code from PAN-OS",
      "order": 2
    },
    "message": {
      "type": "string",
      "title": "Message",
      "description": "A message with more detail about the status",
      "order": 3
    },
    "status": {
      "type": "string",
      "title": "Status",
      "description": "The status of the requested operation e.g. success, error, etc",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
