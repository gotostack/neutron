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

from neutron.db import portforwardings_db
from neutron.extensions import l3
from neutron.extensions import portforwardings
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.extensions import test_l3


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


class PortForwardingsTestExtensionManager(object):

    def get_resources(self):
        l3.RESOURCE_ATTRIBUTE_MAP['routers'].update(
            portforwardings.EXTENDED_ATTRIBUTES_2_0['routers'])
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestPortForwardingsIntPlugin(
        test_l3.TestL3NatIntPlugin,
        portforwardings_db.PortForwardingDbMixin):
    supported_extension_aliases = ["external-net", "router", "portforwarding"]


class TestPortForwardingsL3NatServicePlugin(
        test_l3.TestL3NatServicePlugin,
        portforwardings_db.PortForwardingDbMixin):
    supported_extension_aliases = ["router", "portforwarding"]


class PortForwardingsDBTestCaseBase(object):

    def _add_router_portforwarding_action(self, router_id,
                                          inside_addr, protocol,
                                          outside_port, inside_port,
                                          expected_code=exc.HTTPOk.code,
                                          expected_body=None):
        portforwarding = {"inside_addr": inside_addr,
                          "protocol": protocol,
                          "outside_port": outside_port,
                          "inside_port": inside_port}

        req = self.new_action_request('routers', portforwarding, router_id,
                                      "add_router_portforwarding")
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)
        response = self.deserialize(self.fmt, res)
        if expected_body:
            self.assertEqual(response, expected_body)
        return response

    def _remove_router_portforwarding_action(self, router_id,
                                             portforwarding_id,
                                             expected_code=exc.HTTPOk.code,
                                             expected_body=None):
        prtfwd_info = {"id": portforwarding_id}

        req = self.new_action_request('routers', prtfwd_info, router_id,
                                      "remove_router_portforwarding")
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)
        response = self.deserialize(self.fmt, res)
        if expected_body:
            self.assertEqual(response, expected_body)
        return response

    def test_update_router_with_portforwarding_exception(self):
        with self.router() as r:
            forwardings = [{'outside_port': 2222,
                            'inside_addr': '10.1.0.3',
                            'inside_port': 22,
                            'protocol': 'tcp'
                            }]
            self._update('routers', r['router']['id'],
                         {'router': {'portforwardings':
                                     forwardings}},
                         expected_code=exc.HTTPBadRequest.code)

    def test_router_add_router_portforwarding(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

                # router has subnet, add portforwarding
                body = self._add_router_portforwarding_action(
                    r['router']['id'], '10.0.0.10',
                    'TCP', '22', '22')
                self.assertIn('protocol', body)
                self.assertIn('router_id', body)
                pf_id = body['id']

                # remove portforwarding
                body = self._remove_router_portforwarding_action(
                    r['router']['id'], pf_id)
                self.assertIn('protocol', body)
                self.assertIn('router_id', body)
                self.assertIn('id', body)

                body = self._router_interface_action('remove',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)

    def test_show_router_with_portforwarding_rule(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

                # router has subnet, add portforwarding
                body = self._add_router_portforwarding_action(
                    r['router']['id'], '10.0.0.10',
                    'TCP', '22', '22')
                self.assertIn('protocol', body)
                self.assertIn('router_id', body)
                pf_id = body['id']

                body = self._show('routers', r['router']['id'])
                self.assertIn("portforwardings", body['router'])
                self.assertEqual(pf_id,
                                 body['router']['portforwardings'][0]["id"])

                # remove portforwarding
                body = self._remove_router_portforwarding_action(
                    r['router']['id'], pf_id)
                self.assertIn('protocol', body)
                self.assertIn('router_id', body)
                self.assertIn('id', body)

                body = self._router_interface_action('remove',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)

    def test_router_add_router_portforwarding_nosubnet(self):
        with self.router() as r:
            # router has no subnet
            self._add_router_portforwarding_action(
                r['router']['id'], '10.0.0.3',
                'TCP', '22', '22', expected_code=exc.HTTPBadRequest.code)

    def test_router_add_router_portforwarding_ip_not_in_subnet(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._add_router_portforwarding_action(
                    r['router']['id'], '10.0.10.10',
                    'TCP', '22', '22', expected_code=exc.HTTPBadRequest.code)
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

    def test_router_add_router_portforwarding_invalid_port(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._add_router_portforwarding_action(
                    r['router']['id'], '10.0.0.3',
                    'TCP', '80000', '22',
                    expected_code=exc.HTTPBadRequest.code)
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

    def test_router_add_router_portforwarding_invalid_ip(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._add_router_portforwarding_action(
                    r['router']['id'], '700.0.0.3',
                    'TCP', '22', '22',
                    expected_code=exc.HTTPBadRequest.code)
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

    def test_router_add_router_portforwarding_invalid_protocol(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._add_router_portforwarding_action(
                    r['router']['id'], '10.0.0.3',
                    'SMTP', '22', '22',
                    expected_code=exc.HTTPBadRequest.code)
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

    def test_router_add_router_portforwarding_duplicate_outside_port(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

                # router has subnet, add portforwarding
                body = self._add_router_portforwarding_action(
                    r['router']['id'], '10.0.0.10',
                    'TCP', '22', '22')
                self.assertIn('protocol', body)
                self.assertIn('router_id', body)
                pf_id = body['id']

                # same outside_port
                self._add_router_portforwarding_action(
                    r['router']['id'], '10.0.0.2',
                    'TCP', '22', '22', expected_code=400)

                # remove portforwarding
                body = self._remove_router_portforwarding_action(
                    r['router']['id'], pf_id)
                self.assertIn('protocol', body)
                self.assertIn('router_id', body)
                self.assertIn('id', body)

                body = self._router_interface_action('remove',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)


class PortForwardingsDBIntTestCase(test_l3.L3NatDBIntTestCase,
                                   PortForwardingsDBTestCaseBase):

    def setUp(self, plugin=None):
        if not plugin:
            plugin = ('neutron.tests.unit.extensions.test_portforwardings.'
                      'TestPortForwardingsIntPlugin')
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = PortForwardingsTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(plugin=plugin,
                                                     ext_mgr=ext_mgr)
        self.setup_notification_driver()


class PortForwardingsDBSepTestCase(test_l3.L3NatDBSepTestCase,
                                   PortForwardingsDBTestCaseBase):

    def setUp(self):
        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_portforwardings.'
                     'TestPortForwardingsL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = PortForwardingsTestExtensionManager()
        super(test_l3.L3BaseForSepTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()
