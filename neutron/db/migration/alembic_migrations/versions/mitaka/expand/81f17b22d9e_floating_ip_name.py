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

"""floating ip name

Revision ID: 81f17b22d9e
Revises: 0e66c5227a8a
Create Date: 2016-04-26 10:34:12.102560

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '81f17b22d9e'
down_revision = '0e66c5227a8a'

neutron_milestone = [migration.MITAKA]


def upgrade():
    op.add_column('floatingips',
                  sa.Column('name', sa.String(length=255)))
