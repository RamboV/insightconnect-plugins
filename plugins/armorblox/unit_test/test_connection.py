import os
import sys

sys.path.append(os.path.abspath("../"))
import logging
from unittest import TestCase


from icon_armorblox.connection.connection import Connection
from icon_armorblox.connection.schema import Input


class TestConnection(TestCase):
    def setUp(self) -> None:
        self.connection = Connection()
        self.connection.logger = logging.getLogger("connection logger")

    def test_connection_ok(self):
        self.connection.connect(
            {
                Input.API_KEY: {"secretKey": "any-api-key"},
                Input.TENANT_NAME: "my-tenant-name",
            }
        )
        response = self.connection.test()
        expected_response = {"success": True}
        self.assertEqual(response, expected_response)
