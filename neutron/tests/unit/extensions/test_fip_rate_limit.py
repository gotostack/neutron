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
from neutron.db import fip_rate_limit_db
from neutron.extensions import fip_rate_limit
from neutron.extensions import l3
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.extensions import test_l3


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


class FloatingIPRatelimitTestExtensionManager(object):

    def get_resources(self):
        l3.RESOURCE_ATTRIBUTE_MAP['floatingips'].update(
            fip_rate_limit.EXTENDED_ATTRIBUTES_2_0['floatingips'])
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestFloatingIPRatelimitIntPlugin(
        test_l3.TestL3NatIntPlugin,
        fip_rate_limit_db.FloatingIPRatelimitDbMixin):
    supported_extension_aliases = ["external-net", "router", "fip-rate-limit"]


class TestFloatingIPRatelimitL3NatServicePlugin(
        test_l3.TestL3NatServicePlugin,
        fip_rate_limit_db.FloatingIPRatelimitDbMixin):
    supported_extension_aliases = ["router", "fip-rate-limit"]


class FloatingIPRatelimitDBTestCaseBase(object):

    def test_create_fip_with_rate_limit(self):
        with self.subnet(cidr='11.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            fip = self._make_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'],
                set_context=False,
                rate_limit=10)
            self.assertEqual(fip['floatingip']['rate_limit'], 10)

    def test_create_fip_with_rate_limit_0_not_allowed(self):
        with self.subnet(cidr='11.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            self._make_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'],
                tenant_id='noadmin',
                set_context=True,
                http_status=exc.HTTPBadRequest.code,
                rate_limit=0)

    def test_floatingip_update_rate_limit(self):
        with self.subnet(cidr='11.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            fip = self._make_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'],
                set_context=False,
                rate_limit=10)
            self.assertEqual(fip['floatingip']['rate_limit'], 10)
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertEqual(body['floatingip']['rate_limit'], 10)

            new_rate = 11
            body = self._update('floatingips', fip['floatingip']['id'],
                                {'floatingip': {'rate_limit': new_rate}})
            self.assertEqual(body['floatingip']['rate_limit'], new_rate)

    def test_floatingip_update_rate_limit_0_not_allowed(self):
        with self.subnet(cidr='11.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            fip = self._make_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'],
                set_context=True,
                tenant_id='noadmin',
                rate_limit=10)
            self.assertEqual(fip['floatingip']['rate_limit'], 10)
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertEqual(body['floatingip']['rate_limit'], 10)

            ctx = context.Context('', 'noadmin')
            body = self._update('floatingips', fip['floatingip']['id'],
                                {'floatingip': {'rate_limit': 0}},
                                expected_code=exc.HTTPBadRequest.code,
                                neutron_context=ctx)


class FloatingIPRatelimitDBIntTestCase(test_l3.L3BaseForIntTests,
                                       test_l3.L3NatTestCaseMixin,
                                       FloatingIPRatelimitDBTestCaseBase):

    def setUp(self, plugin=None):
        if not plugin:
            plugin = ('neutron.tests.unit.extensions.test_fip_rate_limit.'
                      'TestFloatingIPRatelimitIntPlugin')
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        cfg.CONF.set_default('enable_fip_rate_limit', True)
        cfg.CONF.set_default('fip_rate_limit_default_rate', 1)
        ext_mgr = FloatingIPRatelimitTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(plugin=plugin,
                                                     ext_mgr=ext_mgr)
        self.setup_notification_driver()


class FloatingIPRatelimitDBSepTestCase(test_l3.L3BaseForSepTests,
                                       test_l3.L3NatTestCaseMixin,
                                       FloatingIPRatelimitDBTestCaseBase):

    def setUp(self):
        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_fip_rate_limit.'
                     'TestFloatingIPRatelimitL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        cfg.CONF.set_default('enable_fip_rate_limit', True)
        cfg.CONF.set_default('fip_rate_limit_default_rate', 1)
        ext_mgr = FloatingIPRatelimitTestExtensionManager()
        super(test_l3.L3BaseForSepTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()
