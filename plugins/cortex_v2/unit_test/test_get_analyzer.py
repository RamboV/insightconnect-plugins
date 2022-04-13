import sys
import os
from unittest import TestCase
from unittest.mock import patch
from icon_cortex_v2.actions.get_analyzer import GetAnalyzer
from icon_cortex_v2.actions.get_analyzer.schema import Input, Output
from insightconnect_plugin_runtime.exceptions import PluginException
from unit_test.mock import Mock

sys.path.append(os.path.abspath("../"))


class TestGetAnalyzer(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.action = Mock.default_connector(GetAnalyzer())
        cls.params = {
            Input.ANALYZER_ID: ""
        }

    @patch("requests.request", side_effect=Mock.mocked_request)
    def test_get_analyzer(self, _mock_request):
        actual = self.action.run(self.params)
        expected = ""
        self.assertEqual(expected, actual)
