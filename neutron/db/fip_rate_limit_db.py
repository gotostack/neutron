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
import sqlalchemy as sa
from sqlalchemy import orm

from neutron._i18n import _
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import model_base
from neutron.extensions import l3

LOG = logging.getLogger(__name__)
fip_opts = [
    cfg.BoolOpt('enable_fip_rate_limit',
                default=False,
                help=_("Whether enable floating IP rate limit.")),
    cfg.IntOpt('fip_rate_limit_default_rate',
               default=0,
               help=_("The default value of the floating IP rate, "
                      "the unit is Mbps. If it is set to 0 then the "
                      "floating IP rate limit will not be enabled event "
                      "set enable_fip_rate_limit to true.")),
]
cfg.CONF.register_opts(fip_opts)


class FloatingIPRatelimit(model_base.BASEV2):
    """Represent floating IP rate limit."""

    __tablename__ = 'fip_rate_limits'
    fip_id = sa.Column(sa.String(36),
                       sa.ForeignKey('floatingips.id', ondelete="CASCADE"),
                       primary_key=True)
    rate_limit = sa.Column(sa.Integer(), nullable=False)

    # Add a relationship to the FloatingIP model in order to instruct
    # SQLAlchemy to eagerly load this association
    floatingip = orm.relationship(l3_db.FloatingIP,
                                  backref=orm.backref("rate",
                                                      lazy='joined',
                                                      uselist=False,
                                                      cascade='delete'))


class FloatingIPRatelimitDbMixin(object):
    """Mixin class to enable floating IP's extra attributes."""

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.FLOATINGIPS, ['_extend_extra_fip_dict'])

    def _extend_extra_fip_dict(self, fip_res, fip_db):
        fip_res['rate_limit'] = cfg.CONF.fip_rate_limit_default_rate
        if fip_db.rate:
            fip_res['rate_limit'] = fip_db.rate['rate_limit']
        return fip_res

    def _create_fip_rate_limit_db(self, context, fip_id, rate_limit):
        rate_limit_db = FloatingIPRatelimit(fip_id=fip_id,
                                            rate_limit=rate_limit)
        context.session.add(rate_limit_db)

    def _process_extra_fip_rate_limit_create(
            self, context, fip_db, fip):
        if not cfg.CONF.enable_fip_rate_limit:
            return

        self._create_fip_rate_limit_db(context,
                                       fip_db['id'],
                                       fip['rate_limit'])

    def _process_extra_fip_rate_limit_update(
            self, context, floatingip_db, fip, floatingip_data):
        if not cfg.CONF.enable_fip_rate_limit:
            return
        if 'rate_limit' in fip:
            rate_limit_db = context.session.query(
                FloatingIPRatelimit).filter_by(
                    fip_id=floatingip_db['id']).one_or_none()
            if rate_limit_db:
                rate_limit_db.update({'rate_limit': fip['rate_limit']})
            else:
                self._create_fip_rate_limit_db(context,
                                               floatingip_db['id'],
                                               fip['rate_limit'])
            floatingip_data.update({'rate_limit': fip['rate_limit']})
