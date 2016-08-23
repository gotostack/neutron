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

from neutron_lib import constants as l3_constants
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron._i18n import _LE
from neutron.common import utils as common_utils
from neutron import manager
from neutron.plugins.common import constants as cons

OPTS = [
    cfg.BoolOpt('enable_l3_metering', default=False,
                help=("Whether enable floating IP and "
                      "router gateway metering.")),
]
cfg.CONF.register_opts(OPTS)
LOG = logging.getLogger(__name__)

# Base identification of generated meter-label-id/meter-rule-id
# for target object(gateway/floatingip/port)
ING_LABEL = '00'
EG_LABEL = '01'
ING_INC_RULE = '0f'
ING_EXC_RULE = '0e'
EG_INC_RULE = '0d'
EG_EXC_RULE = '0c'
INGRESS = 'ingress'
EGRESS = 'egress'


class L3_metering_db_mixin(object):
    """Mixin class to process l3 traffic statistics."""

    @property
    def metering_plugin(self):
        if not cfg.CONF.enable_l3_metering:
            return
        return manager.NeutronManager.get_service_plugins().get(cons.METERING)

    def _get_meter_id(self, raw_id, classfy):
        return raw_id.replace(raw_id[:2], classfy)

    def _get_label_id_pair(self, raw_id):
        ingress_label_id = self._get_meter_id(raw_id, ING_LABEL)
        egress_label_id = self._get_meter_id(raw_id, EG_LABEL)
        return {INGRESS: ingress_label_id, EGRESS: egress_label_id}

    def _get_rule_id_pair(self, raw_id, excluded):
        ingress_rule_classfy = ING_EXC_RULE if excluded else ING_INC_RULE
        egress_rule_classfy = EG_EXC_RULE if excluded else EG_INC_RULE
        ingress_rule_id = self._get_meter_id(raw_id, ingress_rule_classfy)
        egress_rule_id = self._get_meter_id(raw_id, egress_rule_classfy)
        return {INGRESS: ingress_rule_id, EGRESS: egress_rule_id}

    def _process_port_include_rules(self, context, port,
                            labels, tenant_id):
        for ip in port['fixed_ips']:
            sub_id = ip['subnet_id']
            cidr = self._core_plugin.get_subnet(context, sub_id)['cidr']
            self.create_floatingip_rule_pair(context, port['id'],
                                             labels,
                                             tenant_id,
                                             cidr, False)

    def _get_router_interface_ports(self, context, router_id):
        admin_ctx = context.elevated()
        device_filter = {'device_id': [router_id],
                         'device_owner':
                         [l3_constants.DEVICE_OWNER_ROUTER_INTF]}
        return self._core_plugin.get_ports(admin_ctx, filters=device_filter)

    def process_enable_gateway_meter(self, context, router, gw_ip_address):
        """Process router gateway meters.

        The method will be invoked, when enable gateway of router.
        meter-label collect floatingip bandwidth sample through iptables
        chain.
        """
        if self.metering_plugin is None:
            return
        LOG.debug("Create meter labels for "
                  "router %(router_id)s gateway ip %(ip)s.",
                  {'router_id': router['id'], 'ip': gw_ip_address})

        # Create ingress/egress meter label for floatingip.
        fip_lables = self.create_floatingip_label_pair(
            context, router['id'], router['tenant_id'],
            gw_ip_address, router['id'])
        # Create meter rule for attached subnet.
        ports = self._get_router_interface_ports(context, router['id'])
        for port in ports:
            self._process_port_include_rules(context, port,
                                             fip_lables,
                                             router['tenant_id'])

    def process_attach_router_interface_meter(self, context, router, port):
        """Process router interface meters.

        Create meter-rule for attached subnet, which will add new
        meter-rule for meter-label of gateway.
        """
        if self.metering_plugin is None:
            return
        LOG.debug("Process meter rules for "
                  "router %(router_id)s interface port %(port_id)s.",
                  {'router_id': router['id'], 'port_id': port['id']})

        # Create meter rule for attached subnet.
        labels = self._get_label_id_pair(router['id'])
        self._process_port_include_rules(context, port,
                                         labels,
                                         router['tenant_id'])

    def process_associate_floatingip_meter(self, context, floatingip):
        """Process floating IP meters.

        When floatingip associate to VM, creating meter-label and
        meter-label-rule for floatingip and gateway.
        """
        if self.metering_plugin is None:
            return
        LOG.debug("Process meters for floatingip %s.",
                  floatingip['floating_ip_address'])

        fixed_port_id = floatingip['port_id']
        tenant_id = floatingip['tenant_id']
        fip_lables = self.create_floatingip_label_pair(
            context, floatingip['id'],
            tenant_id, floatingip['floating_ip_address'],
            floatingip['router_id'])
        cidr = common_utils.ip_to_cidr(floatingip['fixed_ip_address'])
        self.create_floatingip_rule_pair(context, fixed_port_id,
                                         fip_lables,
                                         tenant_id, cidr)

        router = self.get_router(context, floatingip['router_id'])
        labels = self._get_label_id_pair(router['id'])
        self.create_floatingip_rule_pair(context, fixed_port_id,
                                         labels,
                                         tenant_id, cidr, excluded=True)

    def create_floatingip_label_pair(self, context, raw_id,
                                     tenant_id, floatingip_address,
                                     router_id):
        """Get and create meter labels for floatingip."""
        labels = self._get_label_id_pair(raw_id)
        for direction, label_id in six.iteritems(labels):
            self.create_meter_label(context, label_id,
                                    tenant_id, floatingip_address,
                                    router_id, direction)
        return labels

    def create_floatingip_rule_pair(self, context, raw_id,
                                    labels,
                                    tenant_id, cidr,
                                    excluded=False):
        """Create meter rules pair for floatingip."""
        rules = self._get_rule_id_pair(raw_id, excluded)
        for direction, rule_id in six.iteritems(rules):
            self.create_meter_rule(context, rule_id, labels[direction],
                                   tenant_id, cidr, direction, excluded)

    def process_disable_gateway_meter(self, context, router_id):
        """Process deleting meter labels for router gateway."""
        if self.metering_plugin is None:
            return
        LOG.debug('Deleting meter labels for router %s.', router_id)
        self.delete_fip_label_pair(context, router_id)

    def process_disattach_router_interface_meter(self, context, port):
        """Process deleting meter rules for router interface."""
        if self.metering_plugin is None:
            return
        LOG.debug("Deleting meter rules for port %s.", port['id'])
        for ip in port['fixed_ips']:
            self.delete_fip_rule_pair(context, port['id'])

    def process_disassociate_floatingip_meter(self, context, fip):
        """Process deleting meter labels and rules for floating IP."""
        if self.metering_plugin is None:
            return
        LOG.debug("Deleting meter labels and rules for floating IP %s.",
                  fip['floating_ip_address'])
        self.delete_fip_label_pair(context, fip['id'])
        self.delete_fip_rule_pair(context, fip['port_id'], excluded=True)

    def delete_fip_label_pair(self, context, raw_id):
        labels = self._get_label_id_pair(raw_id)
        for _, label_id in six.iteritems(labels):
            self.delete_meter_label(context, label_id)

    def delete_fip_rule_pair(self, context, raw_id, excluded=False):
        rules = self._get_rule_id_pair(raw_id, excluded)
        for _, rule_id in six.iteritems(rules):
            self.delete_meter_rule(context, rule_id)

    def create_meter_label(self, context, label_id, tenant_id, ip_address,
                           router_id, direction=INGRESS):
        LOG.debug("Creating meter label for IP "
                  "%(ip_address)s in direction %(direction)s with "
                  "relating router_id %(router_id)s .",
                  {'ip_address': ip_address,
                   'router_id': router_id,
                   'direction': direction})
        name = "%s-%s" % (direction, label_id)
        description = "%s label for tenant %s." % (direction, tenant_id)
        param = {'metering_label': {'id': label_id, 'tenant_id': tenant_id,
                                    'name': name,
                                    'description': description,
                                    'shared': False,
                                    'router_id': router_id}}

        try:
            self.metering_plugin.create_metering_label(context, param)
        except Exception:
            LOG.exception(_LE("Unable to create meter label for "
                              "IP %(ip_address)s in direction "
                              "%(direction)s with relating router_id "
                              "%(router_id)s."),
                          {'ip_address': ip_address,
                           'router_id': router_id,
                           'direction': direction})

    def create_meter_rule(self, context, rule_id, label_id, tenant_id,
                          cidr, direction=EGRESS, excluded=False):
        LOG.debug("Creating meter rule with label_id "
                  "%(label_id)s and cidr %(cidr)s"
                  "in direction %(direction)s.",
                  {'label_id': label_id,
                   'cidr': cidr,
                   'direction': direction})
        param = {'metering_label_rule': {'id': rule_id,
                                         'remote_ip_prefix': cidr,
                                         'direction': direction,
                                         'metering_label_id': label_id,
                                         'excluded': excluded,
                                         'tenant_id': tenant_id}}
        try:
            self.metering_plugin.create_metering_label_rule(context,
                                                            param)
        except Exception:
            LOG.exception(_LE("Unable to create meter rule with label_id "
                              "%(label_id)s and cidr %(cidr)s"
                              "in direction %(direction)s."),
                          {'label_id': label_id,
                           'cidr': cidr,
                           'direction': direction})

    def delete_meter_label(self, context, meter_label_id):
        LOG.debug('Deleting target meter label %s.', meter_label_id)
        try:
            self.metering_plugin.delete_metering_label(context,
                                                       meter_label_id)
        except Exception:
            LOG.exception(_LE('Unable to delete meter label %(label_id)s.'),
                          {'label_id': meter_label_id})

    def delete_meter_rule(self, context, meter_rule_id):
        LOG.debug('Deleting meter rule %s.', meter_rule_id)
        try:
            self.metering_plugin.delete_metering_label_rule(context,
                                                            meter_rule_id)
        except Exception:
            LOG.exception(_LE('Unable to delete meter rule %(rule_id)s.'),
                          {'rule_id': meter_rule_id})
