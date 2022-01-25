from komand.exceptions import PluginException
import requests
from requests import Session
from requests.auth import HTTPBasicAuth
from urllib.parse import urlsplit
import json
from icon_fireeye_hx.util import endpoint


class FireEyeAPI:
    def __init__(self, url: str, username: str, password: str, ssl_verify: bool, logger):
        self.url = f"{self.split_url(url)}/hx/api/v3"
        self.ssl_verify = ssl_verify
        self.logger = logger
        self.session = Session()
        self.session.auth = HTTPBasicAuth(username=username, password=password)

    def call_api(
        self, path: str, method: str = "GET", params: dict = None, json_data: dict = None, data: dict = None
    ) -> requests.Response:
        try:
            response = self.session.request(
                method=method.upper(),
                url=f"{self.url}/{path}",
                json=json_data,
                data=data,
                params=params,
                verify=self.ssl_verify,
            )
            if response.status_code in [401, 403]:
                raise PluginException(preset=PluginException.Preset.USERNAME_PASSWORD, data=response.text)
            if response.status_code == 404:
                raise PluginException(preset=PluginException.Preset.NOT_FOUND, data=response.text)
            if 400 <= response.status_code < 500:
                raise PluginException(
                    preset=PluginException.Preset.UNKNOWN,
                    data=response.text,
                )
            if response.status_code > 500:
                raise PluginException(preset=PluginException.Preset.SERVER_ERROR, data=response.text)

            if 200 <= response.status_code < 300:
                return response

            raise PluginException(preset=PluginException.Preset.UNKNOWN, data=response.text)
        except json.decoder.JSONDecodeError as e:
            raise PluginException(preset=PluginException.Preset.INVALID_JSON, data=e)
        except requests.exceptions.HTTPError as e:
            raise PluginException(preset=PluginException.Preset.UNKNOWN, data=e)

    def get_host_id_from_hostname(self, params: dict) -> requests.Response:
        return self.call_api(endpoint.hosts(), params=params).json()

    def get_version(self) -> requests.Response:
        return self.call_api(endpoint.version())

    @staticmethod
    def split_url(url: str) -> str:
        scheme, netloc, paths, queries, fragments = urlsplit(url.strip())  # pylint: disable=unused-variable
        return f"{scheme}://{netloc}"
