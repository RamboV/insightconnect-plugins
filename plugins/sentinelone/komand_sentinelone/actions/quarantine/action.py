import insightconnect_plugin_runtime
from typing import List, Dict, Any

import requests

from .schema import QuarantineInput, QuarantineOutput, Input, Output, Component
from insightconnect_plugin_runtime.exceptions import PluginException

# Custom imports below


class Quarantine(insightconnect_plugin_runtime.Action):
    def __init__(self):
        super(self.__class__, self).__init__(
            name="quarantine",
            description=Component.DESCRIPTION,
            input=QuarantineInput(),
            output=QuarantineOutput(),
        )

    def run(self, params={}):
        agents = list(set(params.get(Input.AGENT, [])))
        whitelist = params.get(Input.WHITELIST, None)
        quarantine_state = params.get(Input.QUARANTINE_STATE)

        successful = []
        failures = []
        for agent in agents:
            agents_founds = self.connection.client.search_agents(agent, results_length=2)

            if not self.__check_agents_found(agents_founds):
                error = f"No agents found using the host information: {agent}."
                self.logger.info(error)
                failures.append(self.__return_failure_details(agent, error))
                continue

            agent_obj = agents_founds[0]
            payload = {"ids": [agent_obj["id"]]}

            try:
                action_type = "connect"
                if quarantine_state:
                    if self.__check_disconnected(agent_obj):
                        self.logger.info(f"Agent: {agent} is already quarantined")
                    if whitelist:
                        self.__find_in_whitelist(agent_obj, whitelist)
                    action_type = "disconnect"
                self.connection.agents_action(action_type, payload)
                successful.append(agent)
            except (PluginException, requests.HTTPError) as error:
                failures.append(self.__return_failure_details(agent, str(error)))
        return {
            Output.SUCCESSFUL: successful,
            Output.FAILURES: failures,
        }

    @staticmethod
    def __check_agents_found(agents: list) -> bool:
        if len(agents) > 1:
            raise PluginException(
                cause="Multiple agents found.",
                assistance="Please provide a unique identifier for the agent to be quarantined.",
            )
        if not agents:
            return False
        return True

    @staticmethod
    def __check_disconnected(agent_obj: dict) -> bool:
        if agent_obj["networkStatus"] in ("disconnected", "disconnecting"):
            return True
        return False

    def __find_in_whitelist(self, agent_obj: dict, whitelist: list):
        for key, value in agent_obj.items():
            if key in ["externalIp", "computerName", "id", "uuid"]:
                self.__raise_when_value_in_whitelist(value, whitelist)
            if key == "networkInterfaces":
                network_dict = value[0]
                for network_key, network_val in network_dict.items():
                    if network_key in ["inet", "inet6"]:
                        for ip_address in network_val:
                            self.__raise_when_value_in_whitelist(ip_address, whitelist)

    def __raise_when_value_in_whitelist(self, value: str, whitelist: List[str]):
        if value in whitelist:
            raise PluginException(
                cause="Agent found in the whitelist.",
                assistance=f"If you would like to block this host, remove {value} from the whitelist and try again.",
            )

    def __return_failure_details(self, agent: str, error: str) -> Dict[str, Any]:
        return {"input_key": agent, "error": error}
