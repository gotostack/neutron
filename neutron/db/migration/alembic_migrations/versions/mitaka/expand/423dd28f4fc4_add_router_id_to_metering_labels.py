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

"""add router id to metering labels

Revision ID: 423dd28f4fc4
Revises: 7e6c94d7da00
Create Date: 2016-08-25 13:36:43.207436

"""

# revision identifiers, used by Alembic.
revision = '423dd28f4fc4'
down_revision = '7e6c94d7da00'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('meteringlabels', sa.Column('router_id',
                  sa.String(length=36), nullable=True))
