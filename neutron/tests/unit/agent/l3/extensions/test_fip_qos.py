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

import mock
from neutron_lib import constants as lib_const
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3.extensions import fip_qos
from neutron.agent.l3 import router_info as l3router
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests import base
from neutron.tests.unit.agent.l3 import test_agent

BASE_TEST_POLICY = {'context': None,
                    'name': 'test1',
                    'id': uuidutils.generate_uuid()}
TEST_POLICY = policy.QosPolicy(**BASE_TEST_POLICY)
TEST_POLICY2 = policy.QosPolicy(context=None,
                                name='test2', id=uuidutils.generate_uuid())
TEST_FIP = "1.1.1.1"
TEST_FIP2 = "2.2.2.2"

HOSTNAME = 'myhost'
_uuid = uuidutils.generate_uuid


class QosExtensionBaseTestCase(test_agent.BasicRouterOperationsFramework):

    def setUp(self):
        super(QosExtensionBaseTestCase, self).setUp()

        self.fip_qos_ext = fip_qos.FipQosAgentExtension()
        self.context = context.get_admin_context()
        self.connection = mock.Mock()
        self.agent_api = mock.Mock()
        self.fip_qos_ext.consume_api(self.agent_api)

        self.policy = policy.QosPolicy(**BASE_TEST_POLICY)
        ingress_rule = (
            rule.QosBandwidthLimitRule(context=None, id=_uuid(),
                                       qos_policy_id=self.policy.id,
                                       max_kbps=1111,
                                       max_burst_kbps=2222,
                                       direction=lib_const.INGRESS_DIRECTION))
        egress_rule = (
            rule.QosBandwidthLimitRule(context=None, id=_uuid(),
                                       qos_policy_id=self.policy.id,
                                       max_kbps=3333,
                                       max_burst_kbps=4444,
                                       direction=lib_const.EGRESS_DIRECTION))
        self.policy.rules = [ingress_rule, egress_rule]

        self.policy2 = policy.QosPolicy(**BASE_TEST_POLICY)
        self.policy2.rules = [ingress_rule]

        self.policy3 = policy.QosPolicy(**BASE_TEST_POLICY)
        self.policy3.rules = [egress_rule]

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ex_gw_port = {'id': _uuid()}
        router = {'id': _uuid(),
                  'gw_port': ex_gw_port,
                  lib_const.FLOATINGIP_KEY: [
                      {'id': _uuid(),
                       'floating_ip_address': '20.0.0.3',
                       'fixed_ip_address': '192.168.0.1',
                       'floating_network_id': _uuid(),
                       'port_id': _uuid(),
                       'host': HOSTNAME,
                       'qos_policy_id': self.policy.id}]}
        self.router_info = l3router.RouterInfo(agent, _uuid(),
                                          router, **self.ri_kwargs)
        self.router_info.ex_gw_port = ex_gw_port


class FipQosExtensionInitializeTestCase(QosExtensionBaseTestCase):

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        call_to_patch = 'neutron.common.rpc.create_connection'
        with mock.patch(call_to_patch,
                        return_value=self.connection) as create_connection:
            self.fip_qos_ext.initialize(
                self.connection, lib_const.L3_AGENT_MODE)
            create_connection.assert_has_calls([mock.call()])
            self.connection.create_consumer.assert_has_calls(
                [mock.call(
                     resources_rpc.resource_type_versioned_topic(
                         resources.QOS_POLICY),
                     [rpc_mock()],
                     fanout=True)]
            )
            subscribe_mock.assert_called_with(mock.ANY, resources.QOS_POLICY)


class FipQosExtensionTestCase(QosExtensionBaseTestCase):

    def setUp(self):
        super(FipQosExtensionTestCase, self).setUp()
        self.fip_qos_ext.initialize(
            self.connection, lib_const.L3_AGENT_MODE)

        self.pull_mock = mock.patch.object(
            self.fip_qos_ext.resource_rpc, 'pull',
            return_value=self.policy).start()

    def _test_new_fip_add(self, func):
        tc_wrapper = mock.Mock()
        with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                               return_value=tc_wrapper):
            func(self.context, self.router_info)
            tc_wrapper.set_ip_rate_limit.assert_has_calls(
                [mock.call('ingress', '20.0.0.3', 1111, 2222),
                 mock.call('egress', '20.0.0.3', 3333, 4444)],
                any_order=True)

    def test_add_router(self):
        self._test_new_fip_add(self.fip_qos_ext.add_router)

    def test_update_router(self):
        self._test_new_fip_add(self.fip_qos_ext.update_router)

    def _test_only_ingress_rule(self, func, policy, direction):
        tc_wrapper = mock.Mock()
        with mock.patch.object(
                self.fip_qos_ext.resource_rpc, 'pull',
                return_value=policy):
            with mock.patch.object(self.fip_qos_ext, '_get_tc_wrapper',
                                   return_value=tc_wrapper):
                func(self.context, self.router_info)
                if direction == 'ingress':
                    calls = [mock.call('ingress', '20.0.0.3', 1111, 2222)]
                else:
                    calls = [mock.call('egress', '20.0.0.3', 3333, 4444)]
                tc_wrapper.set_ip_rate_limit.assert_has_calls(calls)

    def test_add_router_only_ingress(self):
        self._test_only_ingress_rule(self.fip_qos_ext.add_router,
                                     self.policy2,
                                     'ingress')

    def test_add_router_only_egress(self):
        self._test_only_ingress_rule(self.fip_qos_ext.add_router,
                                     self.policy3,
                                     'egress')

    def test_update_router_only_ingress(self):
        self._test_only_ingress_rule(self.fip_qos_ext.add_router,
                                     self.policy2,
                                     'ingress')

    def test_update_router_only_egress(self):
        self._test_only_ingress_rule(self.fip_qos_ext.add_router,
                                     self.policy3,
                                     'egress')


class RouterFipRateLimitMapsTestCase(base.BaseTestCase):

    def setUp(self):
        super(RouterFipRateLimitMapsTestCase, self).setUp()
        self.policy_map = fip_qos.RouterFipRateLimitMaps()

    def test_update_policy(self):
        self.policy_map.update_policy(TEST_POLICY)
        self.assertEqual(TEST_POLICY,
                         self.policy_map.known_policies[TEST_POLICY.id])

    def _set_fips(self):
        self.policy_map.set_fip_policy(TEST_FIP, TEST_POLICY)
        self.policy_map.set_fip_policy(TEST_FIP2, TEST_POLICY2)

    def test_set_fip_policy(self):
        self._set_fips()
        self.assertEqual(TEST_POLICY,
                         self.policy_map.known_policies[TEST_POLICY.id])
        self.assertIn(TEST_FIP,
                      self.policy_map.qos_policy_fips[TEST_POLICY.id])

    def test_get_fip_policy(self):
        self._set_fips()
        self.assertEqual(TEST_POLICY,
                         self.policy_map.get_fip_policy(TEST_FIP))
        self.assertEqual(TEST_POLICY2,
                         self.policy_map.get_fip_policy(TEST_FIP2))

    def test_get_fips(self):
        self._set_fips()
        self.assertEqual([TEST_FIP],
                         list(self.policy_map.get_fips(TEST_POLICY)))

        self.assertEqual([TEST_FIP2],
                         list(self.policy_map.get_fips(TEST_POLICY2)))

    def test_clean_by_fip(self):
        self._set_fips()
        self.policy_map.clean_by_fip(TEST_FIP)
        self.assertNotIn(TEST_POLICY.id, self.policy_map.known_policies)
        self.assertNotIn(TEST_FIP, self.policy_map.fip_policies)
        self.assertIn(TEST_POLICY2.id, self.policy_map.known_policies)

    def test_clean_by_fip_for_unknown_fip(self):
        self.policy_map._clean_policy_info = mock.Mock()
        self.policy_map.clean_by_fip(TEST_FIP)

        self.policy_map._clean_policy_info.assert_not_called()

    def test_find_fip_router_id(self):
        router_id = _uuid()
        self.policy_map.router_floating_ips[router_id] = set([TEST_FIP,
                                                              TEST_FIP2])
        self.assertIsNone(self.policy_map.find_fip_router_id("8.8.8.8"))
        self.assertEqual(router_id,
                         self.policy_map.find_fip_router_id(TEST_FIP))
