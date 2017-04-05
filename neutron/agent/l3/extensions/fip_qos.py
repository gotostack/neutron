#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections

from neutron_lib import constants
from neutron_lib.db import constants as db_consts
from neutron_lib.services.qos import constants as qos_consts
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron.agent.l3 import l3_agent_extension
from neutron.agent.linux import ip_lib
from neutron.agent.linux import l3_tc_lib as tc_lib
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import rpc as n_rpc

LOG = logging.getLogger(__name__)

SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': constants.VALID_DIRECTIONS}
    }
}

# We use the default value to illustrate:
# 1. qos policy does not have some direction `bandwidth_limit`, then we use
#    the default value.
# 2. default value 0 will be treated as no limit.
# 3. if one floating IP's rate was changed from x to 0, the extension will do
#    a tc filter clean procedure.
FIP_DEFAULT_RATE = 0


class RouterFipRateLimitMaps(object):
    def __init__(self):
        self.qos_policy_fips = collections.defaultdict(dict)
        self.known_policies = {}
        self.fip_policies = {}

        """
        The router_floating_ips will be:
            router_floating_ips = {
                router_id_1: set(fip1, fip2),
                router_id_1: set(), # default
            }
        """
        self.router_floating_ips = {}

        """
        The rate limits dict will be:
            xxx_ratelimits = {
                fip_1: (rate, burst),
                fip_2: (None, None), # default
                fip_3: (1, 2),
                fip_4: (3, 4),
            }
        """
        self.ingress_ratelimits = {}
        self.egress_ratelimits = {}

    def update_policy(self, policy):
        self.known_policies[policy.id] = policy

    def get_policy(self, policy_id):
        return self.known_policies.get(policy_id)

    def get_fips(self, policy):
        return self.qos_policy_fips[policy.id].values()

    def get_fip_policy(self, fip):
        policy_id = self.fip_policies.get(fip)
        if policy_id:
            return self.get_policy(policy_id)

    def set_fip_policy(self, fip, policy):
        """Attach a fip to policy and return any previous policy on fip."""
        old_policy = self.get_fip_policy(fip)
        self.known_policies[policy.id] = policy
        self.fip_policies[fip] = policy.id
        self.qos_policy_fips[policy.id][fip] = fip
        if old_policy and old_policy.id != policy.id:
            del self.qos_policy_fips[old_policy.id][fip]
        return old_policy

    def clean_by_fip(self, fip):
        """Detach fip from policy and cleanup data we don't need anymore."""
        if fip in self.fip_policies:
            del self.fip_policies[fip]
            for qos_policy_id, fip_dict in self.qos_policy_fips.items():
                if fip in fip_dict:
                    del fip_dict[fip]
                    if not fip_dict:
                        self._clean_policy_info(qos_policy_id)
                    return
        LOG.debug("Fip qos extension did not have "
                  "information on floating IP %s", fip)

    def _clean_policy_info(self, qos_policy_id):
        del self.qos_policy_fips[qos_policy_id]
        del self.known_policies[qos_policy_id]

    def find_fip_router_id(self, fip):
        for router_id, ips in self.router_floating_ips.items():
            if fip in ips:
                return router_id


class FipQosAgentExtension(
        l3_agent_extension.L3AgentCoreResourceExtension):
    SUPPORTED_RESOURCE_TYPES = [resources.QOS_POLICY]

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""
        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self.policy_map = RouterFipRateLimitMaps()
        self._register_rpc_consumers()

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    @lockutils.synchronized('qos-fip')
    def _handle_notification(self, context, resource_type,
                             qos_policies, event_type):
        if event_type == events.UPDATED:
            for qos_policy in qos_policies:
                self._process_update_policy(qos_policy)

    def _policy_rules_modified(self, old_policy, policy):
        return not (len(old_policy.rules) == len(policy.rules) and
                    all(i in old_policy.rules for i in policy.rules))

    def _process_update_policy(self, qos_policy):
        old_qos_policy = self.policy_map.get_policy(qos_policy.id)
        if old_qos_policy:
            if self._policy_rules_modified(old_qos_policy, qos_policy):
                for fip in self.policy_map.get_fips(qos_policy):
                    router_id = self.policy_map.find_fip_router_id(fip)
                    router_info = self.agent_api.get_router_info(router_id)
                    if not router_info:
                        continue
                    device = self._get_rate_limit_ip_device(router_info)
                    if not device:
                        continue
                    rates = self.get_policy_rates(qos_policy)
                    if rates:
                        self.process_ip_rates(fip, device, rates)
            self.policy_map.update_policy(qos_policy)

    def _process_reset_fip(self, fip):
        self.policy_map.clean_by_fip(fip)

    def _register_rpc_consumers(self):
        registry.register(self._handle_notification, resources.QOS_POLICY)

        self._connection = n_rpc.create_connection()
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        topic = resources_rpc.resource_type_versioned_topic(
            resources.QOS_POLICY)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    def _get_tc_wrapper(self, device):
        return tc_lib.FloatingIPTcCommand(device.name,
                                          namespace=device.namespace)

    def process_ip_rate_limit(self, ip, direction, device, rate, burst):
        ratelimits = direction + "_ratelimits"
        old_rate_limits = getattr(self.policy_map, ratelimits, {})
        old_rate, old_burst = old_rate_limits.get(ip, (None, None))

        if (old_rate and old_rate == rate and old_burst
            and old_burst == burst) or (
                (not old_rate and rate == FIP_DEFAULT_RATE) and
                (not old_burst and burst == FIP_DEFAULT_RATE)):
            # 1. Floating IP rate limit does not change.
            # 2. Floating IP bandwidth does not limit.
            return

        tc_wrapper = self._get_tc_wrapper(device)

        if (rate == FIP_DEFAULT_RATE and burst == FIP_DEFAULT_RATE
                and old_rate != FIP_DEFAULT_RATE
                and old_burst != FIP_DEFAULT_RATE):
            # Floating IP bandwidth was changed to no limit.
            tc_wrapper.clear_ip_rate_limit(direction, ip)
            old_rate_limits.pop(ip, None)
            return

        # Finally, add or update floating IP rate limit
        if ((old_rate > 0 and rate > 0 and old_rate != rate) or
                (old_burst > 0 and burst > 0 and old_burst != burst)):
            tc_wrapper.clear_ip_rate_limit(direction, ip)
        tc_wrapper.set_ip_rate_limit(direction, ip, rate, burst)
        old_rate_limits[ip] = (rate, burst)

    def _get_rate_limit_ip_device(self, router):
        if hasattr(router, "fip_ns") and not hasattr(router, "snat_namespace"):
            # DVR local router
            name = router.fip_ns.get_rtr_ext_device_name(router.router_id)
        elif hasattr(router, "fip_ns") and hasattr(router, "snat_namespace"):
            # DVR edge (or DVR edge ha) router do nothing
            return
        else:
            # Legacy/HA
            ex_gw_port = router.get_ex_gw_port()
            name = router.get_external_device_interface_name(ex_gw_port)
        return ip_lib.IPDevice(name, namespace=router.ns_name)

    def _remove_ip_ratelimit_cache(self, ip, direction):
        # remove cache
        ratelimits = direction + "_ratelimits"
        old_rate_limits = getattr(self.policy_map, ratelimits, {})
        old_rate_limits.pop(ip, None)

    def _remove_fip_rate_limit(self, device, fip_ip):
        tc_wrapper = self._get_tc_wrapper(device)
        for direction in constants.VALID_DIRECTIONS:
            if device.exists():
                tc_wrapper.clear_ip_rate_limit(direction, fip_ip)

            self._remove_ip_ratelimit_cache(fip_ip, direction)

    def get_fip_qos_rates(self, context, fip, policy_id):
        if policy_id is None:
            # Clean the cache
            self._process_reset_fip(fip)
            # process_ip_rate_limit will treat value 0 as
            # cleaning the tc filters if exits or no action.
            return {constants.INGRESS_DIRECTION: {"rate": FIP_DEFAULT_RATE,
                                                  "burst": FIP_DEFAULT_RATE},
                    constants.EGRESS_DIRECTION: {"rate": FIP_DEFAULT_RATE,
                                                 "burst": FIP_DEFAULT_RATE}}
        policy = self.resource_rpc.pull(
            context, resources.QOS_POLICY, policy_id)
        self.policy_map.set_fip_policy(fip, policy)
        return self.get_policy_rates(policy)

    def get_policy_rates(self, policy):
        rates = {}
        for rule in policy.rules:
            if rule.rule_type in SUPPORTED_RULES:
                # Use the first `direction` bandwidth_limit values
                if rule.direction not in rates:
                    rates[rule.direction] = {"rate": rule.max_kbps,
                                             "burst": rule.max_burst_kbps}

        # The return rates dict must contain all directions. If there is no
        # one specific direction qos rule, use the default values.
        for direction in constants.VALID_DIRECTIONS:
            if direction not in rates:
                rates[direction] = {"rate": FIP_DEFAULT_RATE,
                                    "burst": FIP_DEFAULT_RATE}
        return rates

    def process_ip_rates(self, fip, device, rates):
        for direction in constants.VALID_DIRECTIONS:
            rate = rates.get(direction)
            self.process_ip_rate_limit(
                fip, direction, device,
                rate['rate'], rate['burst'])

    def process_floating_ip_addresses(self, context, router):
        device = self._get_rate_limit_ip_device(router)
        if not device:
            return
        floating_ips = router.get_floating_ips()
        current_fips = self.policy_map.router_floating_ips.get(
            router.router_id, set())
        new_fips = set()
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            fip_addr = fip['floating_ip_address']
            new_fips.add(fip_addr)
            rates = self.get_fip_qos_rates(context,
                                           fip_addr,
                                           fip['qos_policy_id'])
            if rates:
                self.process_ip_rates(fip_addr, device, rates)

        self.policy_map.router_floating_ips[router.router_id] = new_fips
        fip_removed = current_fips - new_fips
        for fip in fip_removed:
            self._remove_fip_rate_limit(device, fip)
            self._process_reset_fip(fip)

    @lockutils.synchronized('qos-fip')
    def add_router(self, context, data):
        self.process_floating_ip_addresses(context, data)

    @lockutils.synchronized('qos-fip')
    def update_router(self, context, data):
        self.process_floating_ip_addresses(context, data)

    def delete_router(self, context, data):
        pass

    def ha_state_change(self, context, data):
        pass
