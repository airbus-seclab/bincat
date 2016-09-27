# -*- coding: utf8 -*-
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is derived from work by Willi Ballenthin
# Downloaded from https://github.com/williballenthin/python-pyqt5-hexview
#
import logging
import inspect


def h(i):
    return hex(i).strip("L")


def one(s):
    for c in s:
        return c


class LoggingObject(object):
    def __init__(self):
        self._logger = logging.getLogger("{:s}.{:s}".format(
            self.__module__, self.__class__.__name__))

    def _getCallerFunction(self):
        FUNCTION_NAME_INDEX = 3
        return inspect.stack()[3][FUNCTION_NAME_INDEX]

    def _formatFormatString(self, args):
        return [self._getCallerFunction() + ": " + args[0]] + [a for a in args[1:]]

    def d(self, *args, **kwargs):
        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug(*self._formatFormatString(args), **kwargs)

    def i(self, *args, **kwargs):
        if self._logger.isEnabledFor(logging.INFO):
            self._logger.info(*self._formatFormatString(args), **kwargs)

    def w(self, *args, **kwargs):
        if self._logger.isEnabledFor(logging.WARN):
            self._logger.warn(*self._formatFormatString(args), **kwargs)

    def e(self, *args, **kwargs):
        if self._logger.isEnabledFor(logging.ERROR):
            self._logger.error(*self._formatFormatString(args), **kwargs)
