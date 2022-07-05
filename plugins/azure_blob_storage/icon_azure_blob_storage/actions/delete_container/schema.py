# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "The Delete Container action marks the specified container for deletion. The container and any blobs contained within it are later deleted during garbage collection"


class Input:
    ADDITIONAL_HEADERS = "additional_headers"
    CONTAINER_NAME = "container_name"
    

class Output:
    MESSAGE = "message"
    SUCCESS = "success"
    

class DeleteContainerInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "additional_headers": {
      "type": "object",
      "title": "Additional Headers",
      "description": "Additional headers to pass to the API request",
      "default": "{}",
      "order": 2
    },
    "container_name": {
      "type": "string",
      "title": "Container Name",
      "description": "Name of the container to delete",
      "order": 1
    }
  },
  "required": [
    "container_name"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class DeleteContainerOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "message": {
      "type": "string",
      "title": "Message",
      "description": "Deletion result message",
      "order": 2
    },
    "success": {
      "type": "boolean",
      "title": "Success",
      "description": "Whether the action was successful or not",
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
