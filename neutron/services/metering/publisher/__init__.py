#
# Copyright 2013 Intel Corp.
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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class PublisherBase(object):
    """Base class for plugins that publish data."""

    def __init__(self, parsed_url):
        pass

    @abc.abstractmethod
    def publish_samples(self, context, samples):
        """Publish samples into final conduit."""
