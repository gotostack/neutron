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

import netaddr
from oslo_db import exception as oslo_db_exc
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.extensions import portforwardings


LOG = logging.getLogger(__name__)


class PortForwardingRule(model_base.BASEV2, models_v2.HasId):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"))

    router = orm.relationship(l3_db.Router,
                              backref=orm.backref("portforwarding_list",
                                                  lazy='joined',
                                                  cascade='delete'))
    outside_port = sa.Column(sa.Integer())
    inside_addr = sa.Column(sa.String(15))
    inside_port = sa.Column(sa.Integer())
    # protocol can be either TCP or UDP
    protocol = sa.Column(sa.String(4))
    __table_args__ = (sa.schema.UniqueConstraint('router_id',
                                                 'protocol',
                                                 'outside_port',
                                                 name='rule'),)


class PortForwardingDbMixin(l3_db.L3_NAT_db_mixin):
    """Mixin class to support port forwarding rule configuration on router."""

    def _extend_router_dict_portforwarding(self, router_res, router_db):
        router_res['portforwardings'] = (
            PortForwardingDbMixin._make_extra_portfwd_list(
                router_db['portforwarding_list']))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_router_dict_portforwarding'])

    def update_router(self, context, id, router):
        portfwds = self._get_extra_portfwds_by_router_id(context, id)
        router_updated = super(PortForwardingDbMixin, self).update_router(
            context, id, router)
        router_updated['portforwardings'] = portfwds

        return router_updated

    def _validate_port_range(self, port):
        try:
            port = int(port)
        except Exception:
            raise ValueError()
        if int(port) not in range(1, 65536):
            raise portforwardings.InvalidRulePort(
                port=port)

    def _validate_portforwarding_value(self, portforwarding):
        inside_addr = portforwarding['inside_addr']
        msg = attributes._validate_ip_address(inside_addr)
        if msg:
            raise portforwardings.InvalidInsideAddress(inside_addr=inside_addr)
        self._validate_port_range(portforwarding['outside_port'])
        self._validate_port_range(portforwarding['inside_port'])
        if portforwarding['protocol'].lower() not in ['tcp', 'udp']:
            raise portforwardings.InvalidRuleProtocol(
                protocol=portforwarding['protocol'])

    def _validate_portforwarding_inside_addr(self, context,
                                             router_id, portforwarding):
        query = context.session.query(models_v2.Network).join(models_v2.Port)
        networks = query.filter_by(device_id=router_id)
        subnets = []
        for network in networks:
            subnets.extend(map(lambda x: x['cidr'], network.subnets))

        ip_addr, ip_net = netaddr.IPAddress, netaddr.IPNetwork
        inside_addr = portforwarding['inside_addr']
        valid = any([ip_addr(inside_addr) in ip_net(x) for x in subnets])
        if not valid:
            raise portforwardings.InvalidInsideAddress(inside_addr=inside_addr)

    def _validate_portforwarding(self, context, router_id, portforwarding):
        self._validate_portforwarding_value(portforwarding)
        self._validate_portforwarding_inside_addr(context, router_id,
                                                  portforwarding)

    @staticmethod
    def _make_extra_portfwd_list(portforwardings):
        return [{'outside_port': portfwd['outside_port'],
                 'inside_addr': portfwd['inside_addr'],
                 'inside_port': portfwd['inside_port'],
                 'protocol': portfwd['protocol'],
                 'id': portfwd['id']}
                for portfwd in portforwardings]

    def _get_extra_portfwds_by_router_id(self, context, id):
        query = context.session.query(PortForwardingRule)
        query = query.filter_by(router_id=id)
        return self._make_extra_portfwd_list(query)

    def _make_portforwarding_dict(self, portforwarding, fields=None):
        res = {'id': portforwarding['id'],
               'router_id': portforwarding['router_id'],
               'protocol': portforwarding['protocol'],
               'outside_port': portforwarding['outside_port'],
               'inside_port': portforwarding['inside_port'],
               'inside_addr': portforwarding['inside_addr']}
        return self._fields(res, fields)

    def add_router_portforwarding(self, context, router_id, portforwarding):
        if not portforwarding:
            msg = _("Port forwarding data must be specified")
            raise n_exc.BadRequest(resource='router', msg=msg)

        self._validate_portforwarding(context, router_id, portforwarding)
        try:
            with context.session.begin(subtransactions=True):
                portforwarding_db = PortForwardingRule(
                    id=uuidutils.generate_uuid(),
                    router_id=router_id,
                    protocol=portforwarding['protocol'],
                    outside_port=portforwarding['outside_port'],
                    inside_port=portforwarding['inside_port'],
                    inside_addr=portforwarding['inside_addr'])
                context.session.add(portforwarding_db)
        except oslo_db_exc.DBDuplicateEntry:
            raise portforwardings.DuplicatedOutsidePort(
                port=portforwarding['outside_port'])
        self.l3_rpc_notifier.routers_updated(
            context, [router_id],
            'add_router_portforwarding')
        return self._make_portforwarding_dict(portforwarding_db)

    def _get_portforwarding(self, context, id):
        try:
            pf = self._get_by_id(context, PortForwardingRule, id)
        except exc.NoResultFound:
            raise portforwardings.PortforwardingNotFound(portforwarding_id=id)
        return pf

    def remove_router_portforwarding(self, context, router_id, prtfwd_info):
        if not prtfwd_info or 'id' not in prtfwd_info:
            msg = _("Port forwarding ID must be specified")
            raise n_exc.BadRequest(resource='router', msg=msg)

        portforwarding_id = prtfwd_info['id']
        portforwarding = self._get_portforwarding(context,
                                                  portforwarding_id)
        if router_id != portforwarding['router_id']:
            raise portforwardings.RouterPortforwardingNotFound(
                router_id=router_id,
                portforwarding_id=portforwarding_id)
        with context.session.begin(subtransactions=True):
            context.session.delete(portforwarding)
        self.l3_rpc_notifier.routers_updated(
            context, [router_id],
            'remove_router_portforwarding')
        info = {'id': portforwarding_id,
                'router_id': router_id,
                'protocol': portforwarding['protocol'],
                'outside_port': portforwarding['outside_port'],
                'inside_port': portforwarding['inside_port'],
                'inside_addr': portforwarding['inside_addr']}
        return info
