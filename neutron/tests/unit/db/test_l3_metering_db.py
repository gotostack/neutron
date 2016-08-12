# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from neutron_lib import constants as l3_constants
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron import context
from neutron.db import l3_metering_db
from neutron.tests import base

_uuid = uuidutils.generate_uuid

ROUTER_1 = {'id': 'my_router_id',
            'name': 'foo_router',
            'gw_port_id': 'my_gw_port_id',
            'tenant_id': 'my_tenant_id',
            'admin_state_up': True}
PORT_1 = {'id': 'my_port_id',
        'fixed_ips': [{'subnet_id': 'my_subnet_id',
                       'ip_address': '192.168.100.10'}],
        'mac_address': 'my_mac',
        'device_owner': l3_constants.DEVICE_OWNER_ROUTER_INTF}
FLOATINGIP_1 = {'id': 'my_floatingip_id',
                'tenant_id': 'my_tenant_id',
                'floating_ip_address': '8.8.8.8',
                'floating_network_id': 'ext_network_id',
                'floating_port_id': 'my_floating_port_id',
                'router_id': 'my_router_id',
                'port_id': 'my_fixed_port_id',
                'fixed_ip_address': '1.1.1.1',
                'status': 'active'}
REMOTE_IP = '8.8.8.8'


class L3_metering_db_mixin(base.BaseTestCase):
    def setUp(self):
        super(L3_metering_db_mixin, self).setUp()
        cfg.CONF.set_override('enable_l3_metering', True)
        self.db = l3_metering_db.L3_metering_db_mixin()
        self.db._core_plugin = mock.Mock()
        self.ctx = context.Context('', _uuid())

    @mock.patch('neutron.manager.NeutronManager.get_service_plugins',
                return_value=mock.Mock())
    def test_process_attach_router_interface_meter(self, mock_plugins):
        self.db._core_plugin.get_subnet.return_value = {
            'cidr': '192.168.100.0/24'}
        self.db.create_meter_rule = mock.Mock()
        self.db.process_attach_router_interface_meter(self.ctx, ROUTER_1,
                                                      PORT_1)
        self.assertTrue(self.db.create_meter_rule.called)
        self.assertEqual(2, self.db.create_meter_rule.call_count)
        calls_list = [mock.call(mock.ANY,
                                '0f_port_id',
                                '00_router_id',
                                'my_tenant_id',
                                '192.168.100.0/24',
                                'ingress',
                                False),
                      mock.call(mock.ANY,
                                '0d_port_id',
                                '01_router_id',
                                'my_tenant_id',
                                '192.168.100.0/24',
                                'egress',
                                False)]
        self.db.create_meter_rule.assert_has_calls(calls_list, any_order=True)

    @mock.patch('neutron.manager.NeutronManager.get_service_plugins',
                return_value=mock.Mock())
    def test_process_associate_floatingip_meter(self, mock_plugins):
        self.db._core_plugin.get_port.return_value = PORT_1
        self.db.get_router = mock.Mock(return_value=ROUTER_1)
        self.db.create_meter_label = mock.Mock()
        self.db.process_associate_floatingip_meter(self.ctx, FLOATINGIP_1)
        calls_list = [mock.call(mock.ANY,
                                '00_floatingip_id',
                                'my_tenant_id',
                                '8.8.8.8',
                                'ingress'),
                      mock.call(mock.ANY,
                                '01_floatingip_id',
                                'my_tenant_id',
                                '8.8.8.8',
                                'egress')]
        self.db.create_meter_label.assert_has_calls(calls_list, any_order=True)

    @mock.patch('neutron.manager.NeutronManager.get_service_plugins',
                return_value=mock.Mock())
    def test_process_disable_gateway_meter(self, mock_plugins):
        self.db.delete_meter_label = mock.Mock()
        self.db.process_disable_gateway_meter(self.ctx, ROUTER_1['id'])
        calls_list = [mock.call(mock.ANY, '00_router_id'),
                      mock.call(mock.ANY, '01_router_id')]
        self.db.delete_meter_label.assert_has_calls(calls_list, any_order=True)

    @mock.patch('neutron.manager.NeutronManager.get_service_plugins',
                return_value=mock.Mock())
    def test_process_disattach_router_interface_meter(self, mock_plugins):
        self.db.delete_meter_rule = mock.Mock()
        self.db.process_disattach_router_interface_meter(self.ctx, PORT_1)
        calls_list = [mock.call(mock.ANY, '0f_port_id'),
                      mock.call(mock.ANY, '0d_port_id')]
        self.db.delete_meter_rule.assert_has_calls(calls_list, any_order=True)

    @mock.patch('neutron.manager.NeutronManager.get_service_plugins',
                return_value=mock.Mock())
    def test_process_disassociate_floatingip_meter(self, mock_plugins):
        self.db.delete_meter_label = mock.Mock()
        self.db.delete_meter_rule = mock.Mock()
        self.db.process_disassociate_floatingip_meter(self.ctx, FLOATINGIP_1)
        calls_list_label = [mock.call(mock.ANY, '00_floatingip_id'),
                            mock.call(mock.ANY, '01_floatingip_id')]
        calls_list_rule = [mock.call(mock.ANY, '0e_fixed_port_id'),
                           mock.call(mock.ANY, '0c_fixed_port_id')]
        self.db.delete_meter_label.assert_has_calls(calls_list_label,
                                                    any_order=True)
        self.db.delete_meter_rule.assert_has_calls(calls_list_rule,
                                                   any_order=True)
