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

"""portforwardings

Revision ID: 7e6c94d7da00
Revises: 195176fb410d
Create Date: 2013-12-11 11:47:27.548651

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '7e6c94d7da00'
down_revision = '195176fb410d'

neutron_milestone = [migration.MITAKA]


def upgrade():

    op.create_table('portforwardingrules',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('router_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('outside_port', sa.Integer(), nullable=True),
                    sa.Column('inside_addr', sa.String(length=15),
                              nullable=True),
                    sa.Column('inside_port', sa.Integer(), nullable=True),
                    sa.Column('protocol', sa.String(length=4),
                              nullable=True),
                    sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('router_id', 'protocol',
                                        'outside_port',
                                        name='rule'),
                    )
