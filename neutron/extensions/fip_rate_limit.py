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

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as nexception
from neutron.extensions import l3

EXTENDED_ATTRIBUTES_2_0 = {
    l3.FLOATINGIPS: {
        'rate_limit': {'allow_post': True, 'allow_put': True,
                       'default': 1, 'convert_to': attr.convert_to_int,
                       'validate': {'type:range': [0, 10000]},
                       'is_visible': True}
    }
}


class FloatingIPRatelimitNotFound(nexception.NotFound):
    message = _("Floating IP %(floatingip_id)s rate limit could not be found")


class Fip_rate_limit(extensions.ExtensionDescriptor):
    """Extension class supporting virtual router in HA mode."""

    @classmethod
    def get_name(cls):
        return "Floating IP rate limit extension"

    @classmethod
    def get_alias(cls):
        return "fip-rate-limit"

    @classmethod
    def get_description(cls):
        return "Floating IP rate limit."

    @classmethod
    def get_updated(cls):
        return "2016-05-20T00:00:00-00:00"

    def get_required_extensions(self):
        return ["router"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
