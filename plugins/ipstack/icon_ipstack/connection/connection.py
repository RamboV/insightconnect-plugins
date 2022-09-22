import insightconnect_plugin_runtime
from .schema import ConnectionSchema, Input
from insightconnect_plugin_runtime.exceptions import ConnectionTestException

# Custom imports below
import json


class Connection(insightconnect_plugin_runtime.Connection):
    def __init__(self):
        super(self.__class__, self).__init__(input=ConnectionSchema())
        self.token = None

    def connect(self, params):
        self.token = params.get(Input.CRED_TOKEN).get("secretKey")

    def test(self, params):
        url = (
            "http://api.ipstack.com/"
            + "check"
            + "?access_key="
            + params.get(Input.CRED_TOKEN).get("secretKey")
            + "&output=json"
        )
        try:
            resp = insightconnect_plugin_runtime.helper.open_url(url)
        except Exception as e:
            raise ConnectionTestException(
                cause="Failed to get URL", assistance="Please check your API key is valid and try again"
            )
        return {"success": True}
