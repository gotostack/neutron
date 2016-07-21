# Copyright 2016 OVH SAS
# All Rights Reserved.
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

import mock

from neutron.agent.linux import tc_lib
from neutron.tests import base

DEVICE_NAME = "tap_device"
KERNEL_HZ_VALUE = 1000
BW_LIMIT = 2000  # [kbps]
BURST = 100  # [kbit]
LATENCY = 50  # [ms]

TC_QDISC_OUTPUT = (
    'qdisc tbf 8011: root refcnt 2 rate %(bw)skbit burst %(burst)skbit '
    'lat 50.0ms \n') % {'bw': BW_LIMIT, 'burst': BURST}

TC_FILTERS_OUTPUT = (
    'filter protocol all pref 49152 u32 \nfilter protocol all pref '
    '49152 u32 fh 800: ht divisor 1 \nfilter protocol all pref 49152 u32 fh '
    '800::800 order 2048 key ht 800 \n  match 00000000/00000000 at 0\n  '
    'police 0x1e rate %(bw)skbit burst %(burst)skbit mtu 2Kb action \n'
    'drop overhead 0b \n  ref 1 bind 1'
) % {'bw': BW_LIMIT, 'burst': BURST}


FLOATING_IP_DEVICE_NAME = "qg-device_rfp-device"
FLOATING_IP_ROUTER_NAMESPACE = "qrouter-namespace_snat-namespace"

FLOATING_IP_1 = "172.16.5.146"
FLOATING_IP_2 = "172.16.10.105"
FILETER_ID_1 = "800::800"
FILETER_ID_2 = "800::801"

TC_INGRESS_FILTERS = (
    'filter protocol ip u32 \n'
    'filter protocol ip u32 fh 800: ht divisor 1 \n'
    'filter protocol ip u32 fh %(filter_id1)s order 2048 key '
    'ht 800 bkt 0 '
    'flowid :1  (rule hit 0 success 0)\n'
    '  match IP dst %(fip1)s/32 (success 0 ) \n'
    ' police 0x3 rate 3000Kbit burst 3Mb mtu 64Kb action drop overhead 0b \n'
    'ref 1 bind 1\n'
    '\n'
    ' Sent 111 bytes 222 pkts (dropped 0, overlimits 0) \n'
    'filter protocol ip u32 fh %(filter_id2)s order 2049 key '
    'ht 800 bkt 0 '
    'flowid :1  (rule hit 0 success 0)\n'
    '  match IP dst %(fip2)s/32 (success 0 ) \n'
    ' police 0x1b rate 22000Kbit burst 22Mb mtu 64Kb action drop '
    'overhead 0b \n'
    'ref 1 bind 1\n'
    '\n'
    ' Sent 111 bytes 222 pkts (dropped 0, overlimits 0)\n') % {
        "filter_id1": FILETER_ID_1,
        "fip1": FLOATING_IP_1,
        "filter_id2": FILETER_ID_2,
        "fip2": FLOATING_IP_2}

TC_INGRESS_FILTERS_DUP = TC_INGRESS_FILTERS + (
    'filter protocol ip u32 fh %(filter_id2)s order 2049 key '
    'ht 800 bkt 0 '
    'flowid :1  (rule hit 0 success 0)\n'
    '  match IP dst %(fip2)s/32 (success 0 ) \n'
    ' police 0x1b rate 22000Kbit burst 22Mb mtu 64Kb action drop '
    'overhead 0b \n'
    'ref 1 bind 1\n'
    '\n'
    ' Sent 111 bytes 222 pkts (dropped 0, overlimits 0)\n') % {
        "filter_id2": FILETER_ID_2,
        "fip2": FLOATING_IP_2}

TC_EGRESS_FILTERS = (
    'filter protocol ip u32 \n'
    'filter protocol ip u32 fh 800: ht divisor 1 \n'
    'filter protocol ip u32 fh %(filter_id1)s order 2048 key '
    'ht 800 bkt 0 '
    'flowid :1  (rule hit 0 success 0)\n'
    '  match IP src %(fip1)s/32 (success 0 ) \n'
    ' police 0x4 rate 3000Kbit burst 3Mb mtu 64Kb action drop overhead 0b \n'
    'ref 1 bind 1\n'
    '\n'
    ' Sent 111 bytes 222 pkts (dropped 0, overlimits 0) \n'
    'filter protocol ip u32 fh %(filter_id2)s order 2049 key '
    'ht 800 bkt 0 '
    'flowid :1  (rule hit 0 success 0)\n'
    '  match IP src %(fip2)s/32 (success 0 ) \n'
    ' police 0x1c rate 22000Kbit burst 22Mb mtu 64Kb action drop '
    'overhead 0b \n'
    'ref 1 bind 1\n'
    '\n'
    ' Sent 111 bytes 222 pkts (dropped 0, overlimits 0)\n') % {
        "filter_id1": FILETER_ID_1,
        "fip1": FLOATING_IP_1,
        "filter_id2": FILETER_ID_2,
        "fip2": FLOATING_IP_2}
FILTERS_IDS = {tc_lib.TC_DIRECTION_INGRESS: TC_INGRESS_FILTERS,
               tc_lib.TC_DIRECTION_EGRESS: TC_EGRESS_FILTERS}

INGRESS_QSIC_ID = "ffff:"
EGRESS_QDISC_ID = "8002:"
QDISC_IDS = {tc_lib.TC_DIRECTION_INGRESS: INGRESS_QSIC_ID,
             tc_lib.TC_DIRECTION_EGRESS: EGRESS_QDISC_ID}
TC_QDISCS = (
    'qdisc htb %(egress)s root refcnt 2 r2q 10 default 0 '
    'direct_packets_stat 6\n'
    'qdisc ingress %(ingress)s parent ffff:fff1 ----------------\n') % {
        "egress": "8002:",
        "ingress": "ffff:"}


class BaseUnitConversionTest(object):

    def test_convert_to_kilobits_bare_value(self):
        value = "1000"
        expected_value = 8  # kbit
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_kilobits_bytes_value(self):
        value = "1000b"
        expected_value = 8  # kbit
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_kilobits_bits_value(self):
        value = "1000bit"
        expected_value = tc_lib.bits_to_kilobits(1000, self.base_unit)
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_kilobits_megabytes_value(self):
        value = "1m"
        expected_value = tc_lib.bits_to_kilobits(
            self.base_unit ** 2 * 8, self.base_unit)
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_kilobits_megabits_value(self):
        value = "1mbit"
        expected_value = tc_lib.bits_to_kilobits(
            self.base_unit ** 2, self.base_unit)
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_bytes_wrong_unit(self):
        value = "1Zbit"
        self.assertRaises(
            tc_lib.InvalidUnit,
            tc_lib.convert_to_kilobits, value, self.base_unit
        )

    def test_bytes_to_bits(self):
        test_values = [
            (0, 0),  # 0 bytes should be 0 bits
            (1, 8)   # 1 byte should be 8 bits
        ]
        for input_bytes, expected_bits in test_values:
            self.assertEqual(
                expected_bits, tc_lib.bytes_to_bits(input_bytes)
            )


class TestSIUnitConversions(BaseUnitConversionTest, base.BaseTestCase):

    base_unit = tc_lib.SI_BASE

    def test_bits_to_kilobits(self):
        test_values = [
            (0, 0),  # 0 bites should be 0 kilobites
            (1, 1),  # 1 bit should be 1 kilobit
            (999, 1),  # 999 bits should be 1 kilobit
            (1000, 1),  # 1000 bits should be 1 kilobit
            (1001, 2)   # 1001 bits should be 2 kilobits
        ]
        for input_bits, expected_kilobits in test_values:
            self.assertEqual(
                expected_kilobits,
                tc_lib.bits_to_kilobits(input_bits, self.base_unit)
            )


class TestIECUnitConversions(BaseUnitConversionTest, base.BaseTestCase):

    base_unit = tc_lib.IEC_BASE

    def test_bits_to_kilobits(self):
        test_values = [
            (0, 0),  # 0 bites should be 0 kilobites
            (1, 1),  # 1 bit should be 1 kilobit
            (1023, 1),  # 1023 bits should be 1 kilobit
            (1024, 1),  # 1024 bits should be 1 kilobit
            (1025, 2)   # 1025 bits should be 2 kilobits
        ]
        for input_bits, expected_kilobits in test_values:
            self.assertEqual(
                expected_kilobits,
                tc_lib.bits_to_kilobits(input_bits, self.base_unit)
            )


class TestTcCommand(base.BaseTestCase):
    def setUp(self):
        super(TestTcCommand, self).setUp()
        self.tc = tc_lib.TcCommand(DEVICE_NAME, KERNEL_HZ_VALUE)
        self.bw_limit = "%s%s" % (BW_LIMIT, tc_lib.BW_LIMIT_UNIT)
        self.burst = "%s%s" % (BURST, tc_lib.BURST_UNIT)
        self.latency = "%s%s" % (LATENCY, tc_lib.LATENCY_UNIT)
        self.execute = mock.patch('neutron.agent.common.utils.execute').start()

    def test_check_kernel_hz_lower_then_zero(self):
        self.assertRaises(
            tc_lib.InvalidKernelHzValue,
            tc_lib.TcCommand, DEVICE_NAME, 0
        )
        self.assertRaises(
            tc_lib.InvalidKernelHzValue,
            tc_lib.TcCommand, DEVICE_NAME, -100
        )

    def test_get_filters_bw_limits(self):
        self.execute.return_value = TC_FILTERS_OUTPUT
        bw_limit, burst_limit = self.tc.get_filters_bw_limits()
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst_limit)

    def test_get_filters_bw_limits_when_output_not_match(self):
        output = (
            "Some different "
            "output from command:"
            "tc filters show dev XXX parent ffff:"
        )
        self.execute.return_value = output
        bw_limit, burst_limit = self.tc.get_filters_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst_limit)

    def test_get_filters_bw_limits_when_wrong_units(self):
        output = TC_FILTERS_OUTPUT.replace("kbit", "Xbit")
        self.execute.return_value = output
        self.assertRaises(tc_lib.InvalidUnit, self.tc.get_filters_bw_limits)

    def test_get_tbf_bw_limits(self):
        self.execute.return_value = TC_QDISC_OUTPUT
        bw_limit, burst_limit = self.tc.get_tbf_bw_limits()
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst_limit)

    def test_get_tbf_bw_limits_when_wrong_qdisc(self):
        output = TC_QDISC_OUTPUT.replace("tbf", "different_qdisc")
        self.execute.return_value = output
        bw_limit, burst_limit = self.tc.get_tbf_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst_limit)

    def test_get_tbf_bw_limits_when_wrong_units(self):
        output = TC_QDISC_OUTPUT.replace("kbit", "Xbit")
        self.execute.return_value = output
        self.assertRaises(tc_lib.InvalidUnit, self.tc.get_tbf_bw_limits)

    def test_set_tbf_bw_limit(self):
        self.tc.set_tbf_bw_limit(BW_LIMIT, BURST, LATENCY)
        self.execute.assert_called_once_with(
            ["tc", "qdisc", "replace", "dev", DEVICE_NAME,
             "root", "tbf", "rate", self.bw_limit,
             "latency", self.latency,
             "burst", self.burst],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test_update_filters_bw_limit(self):
        self.tc.update_filters_bw_limit(BW_LIMIT, BURST)
        self.execute.assert_has_calls([
            mock.call(
                ["tc", "qdisc", "del", "dev", DEVICE_NAME, "ingress"],
                run_as_root=True,
                check_exit_code=True,
                log_fail_as_error=True,
                extra_ok_codes=[2]
            ),
            mock.call(
                ['tc', 'qdisc', 'add', 'dev', DEVICE_NAME, "ingress",
                 "handle", tc_lib.INGRESS_QDISC_ID],
                run_as_root=True,
                check_exit_code=True,
                log_fail_as_error=True,
                extra_ok_codes=None
            ),
            mock.call(
                ['tc', 'filter', 'add', 'dev', DEVICE_NAME,
                 'parent', tc_lib.INGRESS_QDISC_ID, 'protocol', 'all',
                 'prio', '49', 'basic', 'police',
                 'rate', self.bw_limit,
                 'burst', self.burst,
                 'mtu', tc_lib.MAX_MTU_VALUE,
                 'drop'],
                run_as_root=True,
                check_exit_code=True,
                log_fail_as_error=True,
                extra_ok_codes=None
            )]
        )

    def test_update_tbf_bw_limit(self):
        self.tc.update_tbf_bw_limit(BW_LIMIT, BURST, LATENCY)
        self.execute.assert_called_once_with(
            ["tc", "qdisc", "replace", "dev", DEVICE_NAME,
             "root", "tbf", "rate", self.bw_limit,
             "latency", self.latency,
             "burst", self.burst],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test_delete_filters_bw_limit(self):
        self.tc.delete_filters_bw_limit()
        self.execute.assert_called_once_with(
            ["tc", "qdisc", "del", "dev", DEVICE_NAME, "ingress"],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=[2]
        )

    def test_delete_tbf_bw_limit(self):
        self.tc.delete_tbf_bw_limit()
        self.execute.assert_called_once_with(
            ["tc", "qdisc", "del", "dev", DEVICE_NAME, "root"],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=[2]
        )

    def test__get_filters_burst_value_burst_not_none(self):
        self.assertEqual(
            BURST, self.tc._get_filters_burst_value(BW_LIMIT, BURST)
        )

    def test__get_filters_burst_no_burst_value_given(self):
        expected_burst = BW_LIMIT * 0.8
        self.assertEqual(
            expected_burst,
            self.tc._get_filters_burst_value(BW_LIMIT, None)
        )

    def test__get_filters_burst_burst_value_zero(self):
        expected_burst = BW_LIMIT * 0.8
        self.assertEqual(
            expected_burst,
            self.tc._get_filters_burst_value(BW_LIMIT, 0)
        )

    def test__get_tbf_burst_value_when_burst_bigger_then_minimal(self):
        result = self.tc._get_tbf_burst_value(BW_LIMIT, BURST)
        self.assertEqual(BURST, result)

    def test__get_tbf_burst_value_when_burst_smaller_then_minimal(self):
        result = self.tc._get_tbf_burst_value(BW_LIMIT, 0)
        self.assertEqual(2, result)


class TestFloatingIPTcCommandBase(base.BaseTestCase):
    def setUp(self):
        super(TestFloatingIPTcCommandBase, self).setUp()
        self.tc = tc_lib.FloatingIPTcCommandBase(
            FLOATING_IP_DEVICE_NAME,
            namespace=FLOATING_IP_ROUTER_NAMESPACE)
        self.execute = mock.patch('neutron.agent.common.utils.execute').start()

    def test__get_qdiscs(self):
        self.tc._get_qdiscs()
        self.execute.assert_called_once_with(
            ['ip', 'netns', 'exec', FLOATING_IP_ROUTER_NAMESPACE,
             'tc', 'qdisc', 'show', 'dev', FLOATING_IP_DEVICE_NAME],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test__get_qdisc_id_for_filter(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdiscs') as get_qdiscs:
            get_qdiscs.return_value = TC_QDISCS
            q1 = self.tc._get_qdisc_id_for_filter(tc_lib.TC_DIRECTION_INGRESS)
            self.assertEqual(q1, INGRESS_QSIC_ID)
            q2 = self.tc._get_qdisc_id_for_filter(tc_lib.TC_DIRECTION_EGRESS)
            self.assertEqual(q2, EGRESS_QDISC_ID)

    def test__add_qdisc(self):
        self.tc._add_qdisc(tc_lib.TC_DIRECTION_INGRESS)
        self.execute.assert_called_with(
            ['ip', 'netns', 'exec', FLOATING_IP_ROUTER_NAMESPACE,
             'tc', 'qdisc', 'add', 'dev', FLOATING_IP_DEVICE_NAME, 'ingress'],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )
        self.tc._add_qdisc(tc_lib.TC_DIRECTION_EGRESS)
        self.execute.assert_called_with(
            ['ip', 'netns', 'exec', FLOATING_IP_ROUTER_NAMESPACE,
             'tc', 'qdisc', 'add', 'dev', FLOATING_IP_DEVICE_NAME] + ['root',
                                                                      'htb'],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test__get_filters(self):
        self.tc._get_filters(INGRESS_QSIC_ID)
        self.execute.assert_called_with(
            ['ip', 'netns', 'exec', FLOATING_IP_ROUTER_NAMESPACE,
             'tc', '-p', '-s', '-d', 'filter', 'show', 'dev',
             FLOATING_IP_DEVICE_NAME,
             'parent', INGRESS_QSIC_ID, 'prio', 1],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test__get_filterid_for_ip(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_filters') as get_filters:
            get_filters.return_value = TC_EGRESS_FILTERS
            f_id = self.tc._get_filterid_for_ip(INGRESS_QSIC_ID, FLOATING_IP_1)
            self.assertEqual(f_id, FILETER_ID_1)

    def test__get_filterid_for_ip_duplicated(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_filters') as get_filters:
            get_filters.return_value = TC_INGRESS_FILTERS_DUP
            self.assertRaises(tc_lib.MultipleFilterIDForIPFound,
                              self.tc._get_filterid_for_ip,
                              INGRESS_QSIC_ID, FLOATING_IP_2)

    def test__get_filterid_for_ip_not_found(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_filters') as get_filters:
            get_filters.return_value = TC_EGRESS_FILTERS
            self.assertRaises(tc_lib.FilterIDForIPNotFound,
                              self.tc._get_filterid_for_ip,
                              INGRESS_QSIC_ID, "1.1.1.1")

    def test__del_filter_by_id(self):
        self.tc._del_filter_by_id(INGRESS_QSIC_ID, FLOATING_IP_1)
        self.execute.assert_called_once_with(
            ['ip', 'netns', 'exec', FLOATING_IP_ROUTER_NAMESPACE,
             'tc', 'filter', 'del', 'dev', FLOATING_IP_DEVICE_NAME,
             'parent', INGRESS_QSIC_ID,
             'prio', 1, 'handle', FLOATING_IP_1, 'u32'],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test__get_qdisc_filters(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_filters') as get_filters:
            get_filters.return_value = TC_EGRESS_FILTERS
            f_ids = self.tc._get_qdisc_filters(INGRESS_QSIC_ID)
            self.assertEqual(f_ids, [FILETER_ID_1, FILETER_ID_2])

    def test__get_filter_statictics_line(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_filters') as get_filters:
            get_filters.return_value = TC_EGRESS_FILTERS
            ret = self.tc._get_filter_statictics_line(INGRESS_QSIC_ID,
                                                      FLOATING_IP_1)
            line = "Sent 111 bytes 222 pkts (dropped 0, overlimits 0)"
            self.assertEqual(line, ret)

    def test__add_filter(self):
        protocol = ['protocol', 'ip']
        prio = ['prio', 1]
        match = ['u32', 'match', 'ip', 'dst', FLOATING_IP_1]
        police = ['police', 'rate', '1Mbit', 'burst', '1Mb',
                  'mtu', '64kb', 'drop', 'flowid', ':1']
        args = protocol + prio + match + police
        cmd = ['tc', 'filter', 'add', 'dev', FLOATING_IP_DEVICE_NAME,
               'parent', INGRESS_QSIC_ID] + args

        self.tc._add_filter(INGRESS_QSIC_ID,
                            tc_lib.TC_DIRECTION_INGRESS,
                            FLOATING_IP_1, 1)
        self.execute.assert_called_once_with(
            ['ip', 'netns', 'exec', FLOATING_IP_ROUTER_NAMESPACE] + cmd,
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test__get_or_create_qdisc(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc1:
            get_disc1.return_value = None
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_add_qdisc'):
                with mock.patch.object(
                        tc_lib.FloatingIPTcCommandBase,
                        '_get_qdisc_id_for_filter') as get_disc2:
                    get_disc2.return_value = INGRESS_QSIC_ID
                    qdisc_id = self.tc._get_or_create_qdisc(
                        tc_lib.TC_DIRECTION_INGRESS)
                    self.assertEqual(INGRESS_QSIC_ID, qdisc_id)

    def test__get_or_create_qdisc_failed(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc1:
            get_disc1.return_value = None
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_add_qdisc'):
                with mock.patch.object(
                        tc_lib.FloatingIPTcCommandBase,
                        '_get_qdisc_id_for_filter') as get_disc2:
                    get_disc2.return_value = None
                    self.assertRaises(tc_lib.FailedToAddQdiscToDevice,
                                      self.tc._get_or_create_qdisc,
                                      tc_lib.TC_DIRECTION_INGRESS)


class TestFloatingIPTcCommand(base.BaseTestCase):
    def setUp(self):
        super(TestFloatingIPTcCommand, self).setUp()
        self.tc = tc_lib.FloatingIPTcCommand(
            FLOATING_IP_DEVICE_NAME,
            namespace=FLOATING_IP_ROUTER_NAMESPACE)
        self.execute = mock.patch('neutron.agent.common.utils.execute').start()

    def _test_get_traffic_counters(self, direction, fip):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc:
            get_disc.return_value = QDISC_IDS.get(direction)

            self.execute.return_value = FILTERS_IDS.get(direction)
            acc = self.tc.get_traffic_counters(direction,
                                               fip)
            ret = {'bytes': 111,
                   'pkts': 222}
            self.assertEqual(ret, acc)

    def test_get_traffic_counters_ingress(self):
        self._test_get_traffic_counters(tc_lib.TC_DIRECTION_INGRESS,
                                        FLOATING_IP_1)

    def test_get_traffic_counters_egress(self):
        self._test_get_traffic_counters(tc_lib.TC_DIRECTION_EGRESS,
                                        FLOATING_IP_1)

    def test_clear_all_filters(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc:
            get_disc.return_value = EGRESS_QDISC_ID
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_get_filters') as get_filters:
                get_filters.return_value = TC_EGRESS_FILTERS
                self.tc.clear_all_filters(tc_lib.TC_DIRECTION_EGRESS)
                self.assertEqual(2, self.execute.call_count)

    def test_set_ip_rate_limit_filter_existed(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc:
            get_disc.return_value = EGRESS_QDISC_ID
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_get_filterid_for_ip') as get_filter:
                get_filter.return_value = FILETER_ID_1
                with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                       '_del_filter_by_id') as del_filter:
                    with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                           '_add_filter') as add_filter:
                        ip = "111.111.111.111"
                        self.tc.set_ip_rate_limit(tc_lib.TC_DIRECTION_EGRESS,
                                                  ip, 1)
                        del_filter.assert_called_once_with(
                            EGRESS_QDISC_ID, FILETER_ID_1)
                        add_filter.assert_called_once_with(
                            EGRESS_QDISC_ID, tc_lib.TC_DIRECTION_EGRESS,
                            ip, 1)

    def test_set_ip_rate_limit_no_qdisc(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc:
            get_disc.return_value = None
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_add_qdisc'):
                with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                       '_get_filters') as get_filters:
                    get_filters.return_value = TC_INGRESS_FILTERS
                    get_disc.return_value = INGRESS_QSIC_ID
                    ip = "111.111.111.111"
                    self.tc.set_ip_rate_limit(tc_lib.TC_DIRECTION_INGRESS,
                                              ip, 1)

                    protocol = ['protocol', 'ip']
                    prio = ['prio', 1]
                    _match = 'dst'
                    match = ['u32', 'match', 'ip', _match, ip]
                    police = ['police', 'rate', "1Mbit", 'burst', "1Mb",
                              'mtu', '64kb', 'drop', 'flowid', ':1']
                    args = protocol + prio + match + police

                    self.execute.assert_called_once_with(
                        ['ip', 'netns', 'exec', FLOATING_IP_ROUTER_NAMESPACE,
                         'tc', 'filter', 'add', 'dev', FLOATING_IP_DEVICE_NAME,
                         'parent', INGRESS_QSIC_ID] + args,
                        run_as_root=True,
                        check_exit_code=True,
                        log_fail_as_error=True,
                        extra_ok_codes=None
                    )

    def test_clear_ip_rate_limit(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc:
            get_disc.return_value = EGRESS_QDISC_ID
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_get_filterid_for_ip') as get_filter_id:
                get_filter_id.return_value = FILETER_ID_1
                self.tc.clear_ip_rate_limit(tc_lib.TC_DIRECTION_EGRESS,
                                            FLOATING_IP_1)

                self.execute.assert_called_once_with(
                    ['ip', 'netns', 'exec', FLOATING_IP_ROUTER_NAMESPACE,
                     'tc', 'filter', 'del', 'dev', FLOATING_IP_DEVICE_NAME,
                     'parent', EGRESS_QDISC_ID,
                     'prio', 1, 'handle', FILETER_ID_1, 'u32'],
                    run_as_root=True,
                    check_exit_code=True,
                    log_fail_as_error=True,
                    extra_ok_codes=None
                )

    def test_get_filter_id_for_ip(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc:
            get_disc.return_value = EGRESS_QDISC_ID
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_get_filterid_for_ip') as get_filter_id:
                self.tc.get_filter_id_for_ip(tc_lib.TC_DIRECTION_EGRESS,
                                             '8.8.8.8')
                get_filter_id.assert_called_once_with(EGRESS_QDISC_ID,
                                                      '8.8.8.8')

    def test_get_existed_filter_ids(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc:
            get_disc.return_value = EGRESS_QDISC_ID
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_get_qdisc_filters') as get_filter_ids:
                self.tc.get_existed_filter_ids(tc_lib.TC_DIRECTION_EGRESS)
                get_filter_ids.assert_called_once_with(EGRESS_QDISC_ID)

    def test_delete_filter_ids(self):
        with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                               '_get_qdisc_id_for_filter') as get_disc:
            get_disc.return_value = EGRESS_QDISC_ID
            with mock.patch.object(tc_lib.FloatingIPTcCommandBase,
                                   '_del_filter_by_id') as del_filter_id:
                self.tc.delete_filter_ids(tc_lib.TC_DIRECTION_EGRESS,
                                          [FILETER_ID_1, FILETER_ID_2])
                del_filter_id.assert_has_calls(
                    [mock.call(EGRESS_QDISC_ID, FILETER_ID_1),
                     mock.call(EGRESS_QDISC_ID, FILETER_ID_2)])
