# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Delete application from a policy"


class Input:
    APPLICATION_NAME = "application_name"
    DEVICE_TYPE = "device_type"
    POLICY_NAME = "policy_name"
    

class Output:
    SUCCESS = "success"
    

class DeleteAppFromPolicyInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "application_name": {
      "type": "string",
      "title": "Application",
      "description": "Application name",
      "order": 1
    },
    "device_type": {
      "type": "string",
      "title": "Device type",
      "description": "Device type",
      "enum": [
        "android",
        "ios"
      ],
      "order": 3
    },
    "policy_name": {
      "type": "string",
      "title": "Policy",
      "description": "Policy name",
      "order": 2
    }
  },
  "required": [
    "application_name",
    "device_type",
    "policy_name"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class DeleteAppFromPolicyOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "success": {
      "type": "object",
      "title": "Success",
      "description": "Return true if action was successfully performed on policy",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
