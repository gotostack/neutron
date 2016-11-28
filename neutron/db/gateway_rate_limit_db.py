#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

from oslo_config import cfg
from oslo_log import log as logging
from sqlalchemy.orm import exc

from neutron._i18n import _
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.extensions import l3

LOG = logging.getLogger(__name__)
gateway_opts = [
    cfg.BoolOpt('enable_gateway_rate_limit',
                default=False,
                help=_("Whether enable gateway rate limit.")),
    cfg.IntOpt('gateway_rate_limit_default_rate',
               default=0,
               help=_("The default value of the gateway rate, "
                      "the unit is Mbps. If it is set to 0 then the "
                      "gateway rate limit will not be enabled event "
                      "set enable_fip_rate_limit to true.")),
]
cfg.CONF.register_opts(gateway_opts)

EXTERNAL_GW_INFO = l3.EXTERNAL_GW_INFO


class gateway_rate_limit_dbonly_mixin(l3_gwmode_db.L3_NAT_dbonly_mixin):
    """Mixin class to add gateway rate limit attributes."""

    # Register dict extend functions for ports and networks
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_router_dict_gateway_rate_limit'])

    def _get_router_gateway_port_rate_limit(self, router_db, gw_port_id):
        router_ports = router_db.attached_ports.all()
        for rp in router_ports:
            if gw_port_id == rp.port_id:
                return rp.rate_limit

    def _extend_router_dict_gateway_rate_limit(self, router_res, router_db):
        gw_port_id = router_db.gw_port_id
        if gw_port_id:
            if cfg.CONF.enable_gateway_rate_limit:
                rate = self._get_router_gateway_port_rate_limit(router_db,
                                                                gw_port_id)
            else:
                rate = cfg.CONF.gateway_rate_limit_default_rate
            router_res[EXTERNAL_GW_INFO]['rate_limit'] = rate

    def _update_router_gw_info(self, context, router_id, info, router=None):
        # Load the router only if necessary
        if not router:
            router = self._get_router(context, router_id)

        # Calls superclass, pass router db object for avoiding re-loading
        super(gateway_rate_limit_dbonly_mixin, self)._update_router_gw_info(
            context, router_id, info, router=router)

        if not cfg.CONF.enable_gateway_rate_limit:
            return

        if info and 'rate_limit' in info:
            rate = info['rate_limit']
        else:
            rate = cfg.CONF.gateway_rate_limit_default_rate

        if router.gw_port:
            self._check_and_update_gw_router_port(context, router_id,
                                                  router.gw_port['id'],
                                                  rate)

        return router

    def _get_router_gateway_port(self, context, router_id, port_id):
        qry = context.session.query(l3_db.RouterPort)
        qry = qry.filter_by(
            port_id=port_id,
            router_id=router_id,
            port_type=l3_db.DEVICE_OWNER_ROUTER_GW
        )
        router_port = qry.one()
        return router_port

    def _check_and_update_gw_router_port(self, context, router_id,
                                         port_id, rate):
        try:
            with context.session.begin(subtransactions=True):
                router_port = self._get_router_gateway_port(context,
                                                            router_id,
                                                            port_id)
                if router_port and router_port.rate_limit != rate:
                    router_port.update({'rate_limit': rate})
        except exc.NoResultFound:
            raise l3.RouterInterfaceNotFound(router_id=router_id,
                                             port_id=port_id)

    def _build_routers_list(self, context, routers, gw_ports):
        routers = super(gateway_rate_limit_dbonly_mixin,
                        self)._build_routers_list(
                            context, routers, gw_ports)
        for rtr in routers:
            gw_port_id = rtr['gw_port_id']
            # Collect gw ports only if available
            if gw_port_id and gw_ports.get(gw_port_id):
                rtr['gw_port'] = gw_ports[gw_port_id]
                if cfg.CONF.enable_gateway_rate_limit:
                    gateway_router_port = self._get_router_gateway_port(
                        context, rtr['id'], gw_port_id)
                    rate = gateway_router_port.rate_limit
                else:
                    rate = cfg.CONF.gateway_rate_limit_default_rate
                # Add gateway rate limit
                rtr['gw_port']['rate_limit'] = rate
        return routers


class gateway_with_rate_limit_db_mixin(gateway_rate_limit_dbonly_mixin,
                                       l3_db.L3_NAT_db_mixin):
    pass
