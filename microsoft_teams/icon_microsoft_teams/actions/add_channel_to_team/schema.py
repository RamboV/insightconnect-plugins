# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = "Add a channel to a team"


class Input:
    CHANNEL_DESCRIPTION = "channel_description"
    CHANNEL_NAME = "channel_name"
    TEAM_NAME = "team_name"
    

class Output:
    SUCCESS = "success"
    

class AddChannelToTeamInput(komand.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "channel_description": {
      "type": "string",
      "title": "Channel Description",
      "description": "Channel description",
      "order": 3
    },
    "channel_name": {
      "type": "string",
      "title": "Channel Name",
      "description": "Channel name",
      "order": 2
    },
    "team_name": {
      "type": "string",
      "title": "Team Name",
      "description": "Team name",
      "order": 1
    }
  },
  "required": [
    "channel_description",
    "channel_name",
    "team_name"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class AddChannelToTeamOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "success": {
      "type": "boolean",
      "title": "Success",
      "description": "Boolean indicating if this action was successful",
      "order": 1
    }
  },
  "required": [
    "success"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
