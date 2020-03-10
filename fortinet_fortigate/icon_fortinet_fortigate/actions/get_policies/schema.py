# GENERATED BY KOMAND SDK - DO NOT EDIT
import komand
import json


class Component:
    DESCRIPTION = ""


class Input:
    pass

class Output:
    POLICIES = "policies"
    

class GetPoliciesInput(komand.Input):
    schema = json.loads("""
   {}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class GetPoliciesOutput(komand.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "policies": {
      "type": "object",
      "title": "Policies",
      "description": "Policies",
      "order": 1
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
