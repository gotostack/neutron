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

import re

from oslo_log import log as logging

from neutron._i18n import _, _LW
from neutron.agent.linux import ip_lib
from neutron.common import exceptions

LOG = logging.getLogger(__name__)

INGRESS_QDISC_ID = "ffff:"
MAX_MTU_VALUE = 65535

SI_BASE = 1000
IEC_BASE = 1024

LATENCY_UNIT = "ms"
BW_LIMIT_UNIT = "kbit"  # kilobits per second in tc's notation
BURST_UNIT = "kbit"  # kilobits in tc's notation

# Those are RATES (bits per second) and SIZE (bytes) unit names from tc manual
UNITS = {
    "k": 1,
    "m": 2,
    "g": 3,
    "t": 4
}

filters_pattern = re.compile(r"police \w+ rate (\w+) burst (\w+)")
tbf_pattern = re.compile(
    r"qdisc (\w+) \w+: \w+ refcnt \d rate (\w+) burst (\w+) \w*")
TC_DIRECTION_INGRESS = "ingress"
TC_DIRECTION_EGRESS = "egress"
RATE_LIMIT_DIRECTIONS = [TC_DIRECTION_INGRESS, TC_DIRECTION_EGRESS]


class InvalidKernelHzValue(exceptions.NeutronException):
    message = _("Kernel HZ value %(value)s is not valid. This value must be "
                "greater than 0.")


class InvalidUnit(exceptions.NeutronException):
    message = _("Unit name '%(unit)s' is not valid.")


class MultipleFilterIDForIPFound(exceptions.Conflict):
    message = _("Multiple filter IDs for IP %(ip)s found.")


class FilterIDForIPNotFound(exceptions.NotFound):
    message = _("Filter ID for IP %(ip)s could not be found.")


class FailedToAddQdiscToDevice(exceptions.NeutronException):
    message = _("Failed to add %(direction)s qdisc "
                "to device %(device)s.")


def convert_to_kilobits(value, base):
    value = value.lower()
    if "bit" in value:
        input_in_bits = True
        value = value.replace("bit", "")
    else:
        input_in_bits = False
        value = value.replace("b", "")
    # if it is now bare number then it is in bits, so we return it simply
    if value.isdigit():
        value = int(value)
        if input_in_bits:
            return bits_to_kilobits(value, base)
        else:
            bits_value = bytes_to_bits(value)
            return bits_to_kilobits(bits_value, base)
    unit = value[-1:]
    if unit not in UNITS.keys():
        raise InvalidUnit(unit=unit)
    val = int(value[:-1])
    if input_in_bits:
        bits_value = val * (base ** UNITS[unit])
    else:
        bits_value = bytes_to_bits(val * (base ** UNITS[unit]))
    return bits_to_kilobits(bits_value, base)


def bytes_to_bits(value):
    return value * 8


def bits_to_kilobits(value, base):
    #NOTE(slaweq): round up that even 1 bit will give 1 kbit as a result
    return int((value + (base - 1)) / base)


class TcCommand(ip_lib.IPDevice):

    def __init__(self, name, kernel_hz, namespace=None):
        if kernel_hz <= 0:
            raise InvalidKernelHzValue(value=kernel_hz)
        super(TcCommand, self).__init__(name, namespace=namespace)
        self.kernel_hz = kernel_hz

    def _execute_tc_cmd(self, cmd, **kwargs):
        cmd = ['tc'] + cmd
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ip_wrapper.netns.execute(cmd, run_as_root=True, **kwargs)

    def get_filters_bw_limits(self, qdisc_id=INGRESS_QDISC_ID):
        cmd = ['filter', 'show', 'dev', self.name, 'parent', qdisc_id]
        cmd_result = self._execute_tc_cmd(cmd)
        if not cmd_result:
            return None, None
        for line in cmd_result.split("\n"):
            m = filters_pattern.match(line.strip())
            if m:
                #NOTE(slaweq): because tc is giving bw limit in SI units
                # we need to calculate it as 1000bit = 1kbit:
                bw_limit = convert_to_kilobits(m.group(1), SI_BASE)
                #NOTE(slaweq): because tc is giving burst limit in IEC units
                # we need to calculate it as 1024bit = 1kbit:
                burst_limit = convert_to_kilobits(m.group(2), IEC_BASE)
                return bw_limit, burst_limit
        return None, None

    def get_tbf_bw_limits(self):
        cmd = ['qdisc', 'show', 'dev', self.name]
        cmd_result = self._execute_tc_cmd(cmd)
        if not cmd_result:
            return None, None
        m = tbf_pattern.match(cmd_result)
        if not m:
            return None, None
        qdisc_name = m.group(1)
        if qdisc_name != "tbf":
            return None, None
        #NOTE(slaweq): because tc is giving bw limit in SI units
        # we need to calculate it as 1000bit = 1kbit:
        bw_limit = convert_to_kilobits(m.group(2), SI_BASE)
        #NOTE(slaweq): because tc is giving burst limit in IEC units
        # we need to calculate it as 1024bit = 1kbit:
        burst_limit = convert_to_kilobits(m.group(3), IEC_BASE)
        return bw_limit, burst_limit

    def set_filters_bw_limit(self, bw_limit, burst_limit):
        """Set ingress qdisc and filter for police ingress traffic on device

        This will allow to police traffic incoming to interface. It
        means that it is fine to limit egress traffic from instance point of
        view.
        """
        #because replace of tc filters is not working properly and it's adding
        # new filters each time instead of replacing existing one first old
        # ingress qdisc should be deleted and then added new one so update will
        # be called to do that:
        return self.update_filters_bw_limit(bw_limit, burst_limit)

    def set_tbf_bw_limit(self, bw_limit, burst_limit, latency_value):
        """Set token bucket filter qdisc on device

        This will allow to limit speed of packets going out from interface. It
        means that it is fine to limit ingress traffic from instance point of
        view.
        """
        return self._replace_tbf_qdisc(bw_limit, burst_limit, latency_value)

    def update_filters_bw_limit(self, bw_limit, burst_limit,
                                qdisc_id=INGRESS_QDISC_ID):
        self.delete_filters_bw_limit()
        return self._set_filters_bw_limit(bw_limit, burst_limit, qdisc_id)

    def update_tbf_bw_limit(self, bw_limit, burst_limit, latency_value):
        return self._replace_tbf_qdisc(bw_limit, burst_limit, latency_value)

    def delete_filters_bw_limit(self):
        #NOTE(slaweq): For limit traffic egress from instance we need to use
        # qdisc "ingress" because it is ingress traffic from interface POV:
        self._delete_qdisc("ingress")

    def delete_tbf_bw_limit(self):
        self._delete_qdisc("root")

    def _set_filters_bw_limit(self, bw_limit, burst_limit,
                              qdisc_id=INGRESS_QDISC_ID):
        cmd = ['qdisc', 'add', 'dev', self.name, 'ingress',
               'handle', qdisc_id]
        self._execute_tc_cmd(cmd)
        return self._add_policy_filter(bw_limit, burst_limit)

    def _delete_qdisc(self, qdisc_name):
        cmd = ['qdisc', 'del', 'dev', self.name, qdisc_name]
        # Return_code=2 is fine because it means
        # "RTNETLINK answers: No such file or directory" what is fine when we
        # are trying to delete qdisc
        return self._execute_tc_cmd(cmd, extra_ok_codes=[2])

    def _get_filters_burst_value(self, bw_limit, burst_limit):
        if not burst_limit:
            # NOTE(slaweq): If burst value was not specified by user than it
            # will be set as 80% of bw_limit to ensure that limit for TCP
            # traffic will work well:
            return float(bw_limit) * 0.8
        return burst_limit

    def _get_tbf_burst_value(self, bw_limit, burst_limit):
        min_burst_value = float(bw_limit) / float(self.kernel_hz)
        return max(min_burst_value, burst_limit)

    def _replace_tbf_qdisc(self, bw_limit, burst_limit, latency_value):
        burst = "%s%s" % (
            self._get_tbf_burst_value(bw_limit, burst_limit), BURST_UNIT)
        latency = "%s%s" % (latency_value, LATENCY_UNIT)
        rate_limit = "%s%s" % (bw_limit, BW_LIMIT_UNIT)
        cmd = [
            'qdisc', 'replace', 'dev', self.name,
            'root', 'tbf',
            'rate', rate_limit,
            'latency', latency,
            'burst', burst
        ]
        return self._execute_tc_cmd(cmd)

    def _add_policy_filter(self, bw_limit, burst_limit,
                           qdisc_id=INGRESS_QDISC_ID):
        rate_limit = "%s%s" % (bw_limit, BW_LIMIT_UNIT)
        burst = "%s%s" % (
            self._get_filters_burst_value(bw_limit, burst_limit), BURST_UNIT)
        #NOTE(slaweq): it is made in exactly same way how openvswitch is doing
        # it when configuing ingress traffic limit on port. It can be found in
        # lib/netdev-linux.c#L4698 in openvswitch sources:
        cmd = [
            'filter', 'add', 'dev', self.name,
            'parent', qdisc_id, 'protocol', 'all',
            'prio', '49', 'basic', 'police',
            'rate', rate_limit,
            'burst', burst,
            'mtu', MAX_MTU_VALUE,
            'drop']
        return self._execute_tc_cmd(cmd)


class FloatingIPTcCommandBase(ip_lib.IPDevice):

    def _execute_tc_cmd(self, cmd, **kwargs):
        cmd = ['tc'] + cmd
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ip_wrapper.netns.execute(cmd, run_as_root=True, **kwargs)

    def _get_qdiscs(self):
        cmd = ['qdisc', 'show', 'dev', self.name]
        return self._execute_tc_cmd(cmd)

    def _get_qdisc_id_for_filter(self, direction):
        qdisc_results = self._get_qdiscs().split('\n')
        for qdisc in qdisc_results:
            if direction == TC_DIRECTION_EGRESS:
                pattern = re.compile(r"qdisc htb (\w+:) *")
            else:
                pattern = re.compile(r"qdisc ingress (\w+:) *")
            m = pattern.match(qdisc)
            if m:
                # No chance to get multiple qdiscs
                return m.group(1)

    def _add_qdisc(self, direction):
        if direction == TC_DIRECTION_EGRESS:
            args = ['root', 'htb']
        else:
            args = ['ingress']
        cmd = ['qdisc', 'add', 'dev', self.name] + args
        self._execute_tc_cmd(cmd)

    def _get_filters(self, qdisc_id):
        cmd = ['-p', '-s', '-d', 'filter', 'show', 'dev', self.name,
               'parent', qdisc_id, 'prio', 1]
        return self._execute_tc_cmd(cmd)

    def _get_filterid_for_ip(self, qdisc_id, ip):
        filterids_for_ip = []
        filter_results = self._get_filters(qdisc_id).split('\n')
        for line in filter_results:
            line = line.strip()
            parts = line.split(" ")
            pattern = re.compile(
                r"filter protocol ip u32 fh (\w+::\w+) *"
            )
            m = pattern.match(line)
            if m:
                filter_id = m.group(1)
                # It matched, so ip/32 is not here. continue
                continue
            elif not line.startswith('match'):
                continue
            if ip + '/32' in parts:
                filterids_for_ip.append(filter_id)
        if len(filterids_for_ip) > 1:
            raise MultipleFilterIDForIPFound(ip=ip)
        if len(filterids_for_ip) == 0:
            raise FilterIDForIPNotFound(ip=ip)
        return filterids_for_ip[0]

    def _del_filter_by_id(self, qdisc_id, filterid):
        cmd = ['filter', 'del', 'dev', self.name,
               'parent', qdisc_id,
               'prio', 1, 'handle', filterid, 'u32']
        self._execute_tc_cmd(cmd)

    def _get_qdisc_filters(self, qdisc_id):
        filterids = []
        filter_results = self._get_filters(qdisc_id).split('\n')
        for line in filter_results:
            line = line.strip()
            pattern = re.compile(
                r"filter protocol ip u32 fh (\w+::\w+) *"
            )
            m = pattern.match(line)
            if m:
                filter_id = m.group(1)
                filterids.append(filter_id)
        return filterids

    def _get_filter_statictics_line(self, qdisc_id, ip):
        filter_results = self._get_filters(qdisc_id).split('\n')
        for index, line in enumerate(filter_results):
            line = line.strip()
            parts = line.split(" ")
            if not line.startswith('match'):
                continue
            if ip + '/32' in parts:
                return filter_results[index + 4].strip()

    def _get_tc_rate_value(self, rate):
        return {'rate': "%dMbit" % rate,
                'burst': "%dMb" % rate}

    def _add_filter(self, qdisc_id, direction, ip, rate):
        protocol = ['protocol', 'ip']
        prio = ['prio', 1]
        _match = 'src' if direction == TC_DIRECTION_EGRESS else 'dst'
        match = ['u32', 'match', 'ip', _match, ip]
        value = self._get_tc_rate_value(rate)
        police = ['police', 'rate', value['rate'], 'burst', value['burst'],
                  'mtu', '64kb', 'drop', 'flowid', ':1']
        args = protocol + prio + match + police
        cmd = ['filter', 'add', 'dev', self.name,
               'parent', qdisc_id] + args
        self._execute_tc_cmd(cmd)

    def _get_or_create_qdisc(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            self._add_qdisc(direction)
            qdisc_id = self._get_qdisc_id_for_filter(direction)
            if not qdisc_id:
                raise FailedToAddQdiscToDevice(direction=direction,
                                               device=self.name)
        return qdisc_id


class FloatingIPTcCommand(FloatingIPTcCommandBase):

    def get_traffic_counters(self, direction, ip):
        # RESERVED: for future use.
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        line = self._get_filter_statictics_line(qdisc_id, ip)
        pattern = re.compile(
            r"Sent (\w+) bytes (\w+) pkts *"
        )
        m = pattern.match(line)
        acc = {'pkts': 0, 'bytes': 0}
        if m:
            acc['bytes'] += int(m.group(1))
            acc['pkts'] += int(m.group(2))
        return acc

    def clear_all_filters(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        filterids = self._get_qdisc_filters(qdisc_id)
        for filterid in filterids:
            self._del_filter_by_id(qdisc_id, filterid)

    def set_ip_rate_limit(self, direction, ip, rate):
        qdisc_id = self._get_or_create_qdisc(direction)
        try:
            filter_id = self._get_filterid_for_ip(qdisc_id, ip)
            if filter_id:
                LOG.warning(_LW("Filter %(filter)s for IP %(ip)s in "
                                "%(direction)s qdisc"
                                "already existed."),
                            {'filter': filter_id,
                             'ip': ip,
                             'direction': direction})
        except FilterIDForIPNotFound:
            self._add_filter(qdisc_id, direction, ip, rate)
        except MultipleFilterIDForIPFound:
            raise

    def clear_ip_rate_limit(self, direction, ip):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        try:
            filterid = self._get_filterid_for_ip(qdisc_id, ip)
            if filterid:
                self._del_filter_by_id(qdisc_id, filterid)
        except FilterIDForIPNotFound:
            LOG.warning(_LW("No filter found for %s, skipping filter delete "
                            "action."), ip)
        except MultipleFilterIDForIPFound:
            raise
