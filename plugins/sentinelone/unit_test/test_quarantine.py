import os
import sys

sys.path.append(os.path.abspath("../"))

from unittest import TestCase
from unittest.mock import patch

from komand_sentinelone.actions.quarantine import Quarantine
from komand_sentinelone.actions.quarantine.schema import Input, Output

from util import Util


class TestQuarantine(TestCase):
    @classmethod
    @patch("requests.post", side_effect=Util.mocked_requests_get)
    def setUpClass(cls, mock_request) -> None:
        cls.action = Util.default_connector(Quarantine())

    @patch("requests.request", side_effect=Util.mocked_requests_get)
    @patch("requests.get", side_effect=Util.mocked_requests_get)
    def test_should_success(self, mock_request, mock_get):
        expected = {
            Output.SUCCESSFUL: ["hostname123"],
            Output.FAILURES: [],
        }
        actual = self.action.run({Input.AGENT: ["hostname123"], Input.QUARANTINE_STATE: True})
        self.assertEqual(expected, actual)
