#
# Copyright 2013-2014 eNovance
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
"""Tests for neutron/services/metering/publisher/udp.py
"""

import datetime
import socket

import mock
import msgpack
from oslo_config import fixture as fixture_config
from oslotest import base

from neutron.services.metering.publisher import udp
from neutron.services.metering.publisher import utils


COUNTER_SOURCE = 'testsource'


class TestUDPPublisher(base.BaseTestCase):
    test_data = [
        dict(
            id='test01',
            name='test',
            type='cumulative',
            unit='',
            volume=1,
            user_id='test',
            project_id='test',
            resource_id='test_run_tasks',
            timestamp=datetime.datetime.utcnow().isoformat(),
            resource_metadata={'name': 'TestPublish'},
            source=COUNTER_SOURCE,
        ),
        dict(
            id='test02',
            name='test2',
            type='cumulative',
            unit='',
            volume=1,
            user_id='test',
            project_id='test',
            resource_id='test_run_tasks',
            timestamp=datetime.datetime.utcnow().isoformat(),
            resource_metadata={'name': 'TestPublish'},
            source=COUNTER_SOURCE,
        ),
        dict(
            id='test03',
            name='test2',
            type='cumulative',
            unit='',
            volume=1,
            user_id='test',
            project_id='test',
            resource_id='test_run_tasks',
            timestamp=datetime.datetime.utcnow().isoformat(),
            resource_metadata={'name': 'TestPublish'},
            source=COUNTER_SOURCE,
        ),
        dict(
            id='test04',
            name='test3',
            type='cumulative',
            unit='',
            volume=1,
            user_id='test',
            project_id='test',
            resource_id='test_run_tasks',
            timestamp=datetime.datetime.utcnow().isoformat(),
            resource_metadata={'name': 'TestPublish'},
            source=COUNTER_SOURCE,
        ),
    ]

    @staticmethod
    def _make_fake_socket(published):
        def _fake_socket_socket(family, type):
            def record_data(msg, dest):
                published.append((msg, dest))

            udp_socket = mock.Mock()
            udp_socket.sendto = record_data
            return udp_socket

        return _fake_socket_socket

    def setUp(self):
        super(TestUDPPublisher, self).setUp()
        self.CONF = self.useFixture(fixture_config.Config()).conf
        self.CONF.publisher.telemetry_secret = 'not-so-secret'

    def _check_udp_socket(self, expected_addr_family):
        with mock.patch.object(socket, 'socket') as mock_socket:
            udp.UDPPublisher()
            mock_socket.assert_called_with(expected_addr_family,
                                           socket.SOCK_DGRAM)

    def test_publisher_udp_socket_ipv4(self):
        self.CONF.set_override('udp_address', '127.0.0.1', 'publisher')
        self._check_udp_socket(socket.AF_INET)

    def test_publisher_udp_socket_ipv6(self):
        self.CONF.set_override('udp_address', '[::1]', 'publisher')
        self._check_udp_socket(socket.AF_INET6)

    def test_published(self):
        self.CONF.set_override('udp_address', '127.0.0.1', 'publisher')
        self.CONF.set_override('shrink_metadata', False, 'publisher')
        self.data_sent = []
        with mock.patch('socket.socket',
                        self._make_fake_socket(self.data_sent)):
            publisher = udp.UDPPublisher()
        publisher.publish_samples(None,
                                  self.test_data)

        self.assertEqual(4, len(self.data_sent))

        sent_counters = []

        for data, dest in self.data_sent:
            counter = msgpack.loads(data, encoding="utf-8")
            sent_counters.append(counter)

            # Check destination
            self.assertEqual(('127.0.0.1',
                              self.CONF.publisher.udp_port), dest)

        # Check that counters are equal
        def sort_func(counter):
            return counter['counter_name']

        counters = [utils.meter_message_from_sample(d, False)
                    for d in self.test_data]
        counters.sort(key=sort_func)
        sent_counters.sort(key=sort_func)
        self.assertEqual(counters, sent_counters)

    @staticmethod
    def _raise_ioerror(*args):
        raise IOError

    def _make_broken_socket(self, family, type):
        udp_socket = mock.Mock()
        udp_socket.sendto = self._raise_ioerror
        return udp_socket

    def test_publish_error(self):
        with mock.patch('socket.socket',
                        self._make_broken_socket):
            publisher = udp.UDPPublisher()
        publisher.publish_samples(None, self.test_data)
