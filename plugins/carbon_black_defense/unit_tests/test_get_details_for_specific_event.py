import sys
import os
from unittest import TestCase
from unittest.mock import patch
from komand_carbon_black_defense.actions.get_details_for_specific_event import GetDetailsForSpecificEvent
from komand_carbon_black_defense.actions.get_details_for_specific_event.schema import (
    Input as GetDetailsForSpecificEventSchemaInput,
)
from unit_tests.util import Util
from insightconnect_plugin_runtime.exceptions import PluginException

from unit_tests.mock import (
    mock_request,
)

sys.path.append(os.path.abspath("../tests/"))


class TestGetDetailsForSpecificEvent(TestCase):
    def setUp(self) -> None:
        self.connection, self.action = Util.default_connector(GetDetailsForSpecificEvent())

    # approach: test valid requests and error handling for common responses
    # test get details for specific event with valid input
    @patch("requests.request", side_effect=mock_request)
    def test_get_details_for_specific_event(self, _mock_req):
        actual = self.action.run(
            {
                GetDetailsForSpecificEventSchemaInput.EVENT_IDS: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            }
        )
        expected = {
            "success": True,
            "results": [
                {
                    "backend_timestamp": "2000-01-01T00:00:00.000Z",
                    "device_group_id": 0,
                    "device_id": 1234567,
                    "device_name": "wb-auto-qa",
                    "device_policy_id": 6525,
                    "device_timestamp": "2000-01-01T00:00:00.000Z",
                    "enriched": True,
                    "enriched_event_type": "NETWORK",
                    "event_description": "The operation was <accent>blocked by Cb Defense</accent>.",
                    "event_id": "9de5069c5afe602b2ea0a04b66beb2c0",
                    "event_network_inbound": False,
                    "event_network_local_ipv4": "192.0.2.0/24",
                    "event_network_location": "Times Square,NY,United States",
                    "event_network_protocol": "TCP",
                    "event_network_remote_ipv4": "203.0.113.0/24",
                    "event_network_remote_port": 443,
                    "event_type": "netconn",
                    "ingress_time": 1647340061569,
                    "legacy": True,
                    "org_id": "44d88612fea8a8f36de82e1278abb02f",
                    "parent_guid": "44d88612fea8a8f36de82e1278abb02f-0049ffdb-000003c4-00000000-1d8336797e1b8e5",
                    "parent_pid": 123,
                    "process_guid": "44d88612fea8a8f36de82e1278abb02f-0049ffdb-0000175c-00000000-1d836263d49edea",
                    "process_hash": [
                        "9de5069c5afe602b2ea0a04b66beb2c0",
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    ],
                    "process_name": "c:\\windows\\system32\\setup.exe",
                    "process_pid": [1234],
                    "process_username": ["user1"],
                    "sensor_action": ["DENY", "BLOCK"],
                }
            ],
            "approximate_unaggregated": 100,
            "num_aggregated": 10,
            "num_available": 1,
            "num_found": 100,
            "contacted": 48,
            "completed": 48,
        }
        self.assertEqual(actual, expected)

    # test get details for specific event with invalid credentials
    @patch("requests.request", side_effect=mock_request)
    def test_get_details_for_specific_event_unauthorized(self, _mock_req):
        with self.assertRaises(PluginException) as exception:
            self.connection.host = "url_invalid"
            self.action.run(
                {
                    GetDetailsForSpecificEventSchemaInput.EVENT_IDS: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                }
            )
        cause = "Either the organization key, API key, or connector ID configured in your connection is invalid."
        self.assertEqual(exception.exception.cause, cause)

    # test get details for specific event with an invalid org key
    @patch("requests.request", side_effect=mock_request)
    def test_get_details_for_specific_event_forbidden(self, _mock_req):
        with self.assertRaises(PluginException) as exception:
            self.connection.org_key = "org_key_forbidden"
            self.action.run(
                {
                    GetDetailsForSpecificEventSchemaInput.EVENT_IDS: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                }
            )
        cause = (
            "Access to resource at url/api/investigate/v2/orgs/org_key_forbidden/enriched_events/detail_jobs is "
            "forbidden. The client has authenticated but does not have permission to perform the POST operation."
        )
        self.assertEqual(exception.exception.cause, cause)
