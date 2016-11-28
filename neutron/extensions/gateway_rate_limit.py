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

from neutron.api import extensions
from neutron.api.v2 import attributes as attrs
from neutron.extensions import l3

EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        l3.EXTERNAL_GW_INFO: {
            'allow_post': True, 'allow_put': True,
            'is_visible': True, 'default': None,
            'enforce_policy': True,
            'validate': {
                'type:dict_or_nodata': {
                    'network_id': {'type:uuid': None,
                                   'required': True},
                    'enable_snat': {'type:boolean': None, 'required': False,
                                    'convert_to': attrs.convert_to_boolean},
                    'external_fixed_ips': {
                        'convert_list_to':
                            attrs.convert_kvp_list_to_dict,
                        'type:fixed_ips': None,
                        'default': None,
                        'required': False},
                    'rate_limit': {
                        'default': 0,
                        'convert_to': attrs.convert_to_int,
                        'validate': {'type:range': [0, 10000]}},
                }
            }
        }
    }
}


class Gateway_rate_limit(extensions.ExtensionDescriptor):
    """Extension class supporting virtual router in HA mode."""

    @classmethod
    def get_name(cls):
        return "Router gateway rate limit extension"

    @classmethod
    def get_alias(cls):
        return "gateway-rate-limit"

    @classmethod
    def get_description(cls):
        return "Router gateway rate limit."

    @classmethod
    def get_updated(cls):
        return "2016-05-24T00:00:00-00:00"

    def get_required_extensions(self):
        return ["router"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
