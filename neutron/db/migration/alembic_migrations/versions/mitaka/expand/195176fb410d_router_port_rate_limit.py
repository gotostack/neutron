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

"""router port rate limit

Revision ID: 195176fb410d
Revises: 594422d373ee
Create Date: 2016-04-28 12:38:09.872706

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '195176fb410d'
down_revision = '594422d373ee'

neutron_milestone = [migration.MITAKA]


def upgrade():
    op.add_column('routerports', sa.Column(u'rate_limit',
                                           sa.Integer(), autoincrement=False,
                                           nullable=False, default=0))
