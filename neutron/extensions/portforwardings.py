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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc


# Duplicated Outside Port Exceptions
class DuplicatedOutsidePort(n_exc.InvalidInput):
    message = _("Outside port %(port)s has already been used.")


class InvalidInsideAddress(n_exc.InvalidInput):
    message = _("Inside address %(inside_addr)s does not match "
                "any subnets in this router.")


class InvalidRuleProtocol(n_exc.InvalidInput):
    message = _("Invalid protocol %(protocol)s: only tcp/udp is supported")


class InvalidRulePort(n_exc.InvalidInput):
    message = _("Invalid port %(port)s: port number"
                " value between 1 and 65535.")


class PortforwardingNotFound(n_exc.NotFound):
    message = _("Port forwarding %(portforwarding_id)s could not be found")


class RouterPortforwardingNotFound(n_exc.NotFound):
    message = _("Router %(router_id)s does not have "
                "a port forwarding with id %(portforwarding_id)s")

# Attribute Map
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        'portforwardings': {
            'allow_post': False, 'allow_put': False,
            'is_visible': True
        },
    }
}


class Portforwardings(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Port Forwarding"

    @classmethod
    def get_alias(cls):
        return "portforwarding"

    @classmethod
    def get_description(cls):
        return "Expose internal TCP/UDP port to external network"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/portforwarding/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2015-09-24T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            attributes.PLURALS.update({'portforwardings': 'portforwarding'})
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
