#
# Copyright 2016 eNovance
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
"""Publish a sample using an UDP mechanism
"""

import socket

import msgpack
from oslo_config import cfg
from oslo_log import log
from oslo_utils import netutils

from neutron._i18n import _LW
from neutron.services.metering import publisher
from neutron.services.metering.publisher import utils

OPTS = [
    cfg.StrOpt('udp_address',
               default='0.0.0.0',
               help='Address to which the UDP socket is bound. Set to '
               'an empty string to disable.'),
    cfg.IntOpt('udp_port',
               default=4952,
               help='Port to which the UDP socket is bound.'),
]

cfg.CONF.register_opts(OPTS, group="publisher")

LOG = log.getLogger(__name__)


class UDPPublisher(publisher.PublisherBase):
    def __init__(self):
        self.host, self.port = netutils.parse_host_port(
            cfg.CONF.publisher.udp_address,
            default_port=cfg.CONF.publisher.udp_port)
        self.shrink_metadata = cfg.CONF.publisher.shrink_metadata
        if netutils.is_valid_ipv6(self.host):
            addr_family = socket.AF_INET6
        else:
            addr_family = socket.AF_INET
        self.socket = socket.socket(addr_family,
                                    socket.SOCK_DGRAM)

    def publish_samples(self, context, samples):
        """Send a metering message for publishing

        :param context: Execution context from the service or RPC call
        :param samples: Samples from pipeline after transformation
        """

        for sample in samples:
            msg = utils.meter_message_from_sample(sample,
                                                  self.shrink_metadata)
            host = self.host
            port = self.port
            LOG.debug("Publishing sample %(msg)s over UDP to "
                      "%(host)s:%(port)d" % {'msg': msg, 'host': host,
                                             'port': port})
            try:
                self.socket.sendto(msgpack.dumps(msg),
                                   (self.host, self.port))
            except Exception as e:
                LOG.warning(_LW("Unable to send sample over UDP"))
                LOG.exception(e)
