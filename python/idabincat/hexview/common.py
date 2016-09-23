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
