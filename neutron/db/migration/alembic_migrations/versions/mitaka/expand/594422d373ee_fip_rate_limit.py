# Copyright 2016 OpenStack Foundation
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

"""fip rate limit

Revision ID: 594422d373ee
Revises: 81f17b22d9e
Create Date: 2016-04-26 17:16:10.323756

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '594422d373ee'
down_revision = '81f17b22d9e'

neutron_milestone = [migration.MITAKA]


def upgrade():
    op.create_table('fip_rate_limits',
                    sa.Column('fip_id', sa.String(length=36),
                              nullable=False),
                    sa.Column(u'rate_limit',
                              sa.Integer(), autoincrement=False,
                              nullable=False, default=0),
                    sa.ForeignKeyConstraint(['fip_id'], ['floatingips.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('fip_id'),
                    )
