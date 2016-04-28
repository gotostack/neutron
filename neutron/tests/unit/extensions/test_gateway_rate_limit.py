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
#

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
from webob import exc

from neutron import context
from neutron.db import gateway_rate_limit_db
from neutron.extensions import gateway_rate_limit
from neutron.extensions import l3
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.extensions import test_l3


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


class GatewayRatelimitTestExtensionManager(object):

    def get_resources(self):
        l3.RESOURCE_ATTRIBUTE_MAP['routers'].update(
            gateway_rate_limit.EXTENDED_ATTRIBUTES_2_0['routers'])
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestGatewayRatelimitIntPlugin(
        test_l3.TestL3NatIntPlugin,
        gateway_rate_limit_db.gateway_with_rate_limit_db_mixin):
    supported_extension_aliases = ["external-net",
                                   "router",
                                   "gateway-rate-limit"]


class TestGatewayRatelimitL3NatServicePlugin(
        test_l3.TestL3NatServicePlugin,
        gateway_rate_limit_db.gateway_with_rate_limit_db_mixin):
    supported_extension_aliases = ["router",
                                   "gateway-rate-limit"]


class GatewayRatelimitDBTestCaseBase(object):

    def test_create_router_gateway_with_rate_limit(self):
        with self.subnet(cidr='11.0.0.0/24') as public_sub,\
                self.router() as r:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                rate_limit=10)
            self.assertEqual(
                res['router']['external_gateway_info']['rate_limit'], 10)

    def test_update_router_gateway_rate_limit(self):
        with self.subnet(cidr='11.0.0.0/24') as public_sub,\
                self.router() as r:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                rate_limit=10)
            self.assertEqual(
                res['router']['external_gateway_info']['rate_limit'], 10)

            # update router gateway
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                rate_limit=11)
            self.assertEqual(
                res['router']['external_gateway_info']['rate_limit'], 11)

    def test_router_add_gateway_tenant_ctx_with_rate_0_not_allowed(self):
        with self.router(tenant_id='noadmin',
                         set_context=True) as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                ctx = context.Context('', 'noadmin')
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'],
                    neutron_context=ctx,
                    expected_code=exc.HTTPBadRequest.code,
                    rate_limit=0)


class GatewayRatelimitDBIntTestCase(test_l3.L3BaseForIntTests,
                                    test_l3.L3NatTestCaseMixin,
                                    GatewayRatelimitDBTestCaseBase):

    def setUp(self, plugin=None):
        if not plugin:
            plugin = ('neutron.tests.unit.extensions.test_gateway_rate_limit.'
                      'TestGatewayRatelimitIntPlugin')
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        cfg.CONF.set_default('enable_gateway_rate_limit', True)
        cfg.CONF.set_default('gateway_rate_limit_default_rate', 1)
        ext_mgr = GatewayRatelimitTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(plugin=plugin,
                                                     ext_mgr=ext_mgr)
        self.setup_notification_driver()


class GatewayRatelimitDBSepTestCase(test_l3.L3BaseForSepTests,
                                    test_l3.L3NatTestCaseMixin,
                                    GatewayRatelimitDBTestCaseBase):

    def setUp(self):
        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_gateway_rate_limit.'
                     'TestGatewayRatelimitL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        cfg.CONF.set_default('enable_gateway_rate_limit', True)
        cfg.CONF.set_default('gateway_rate_limit_default_rate', 1)
        ext_mgr = GatewayRatelimitTestExtensionManager()
        super(test_l3.L3BaseForSepTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()
