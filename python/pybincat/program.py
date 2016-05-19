
import ConfigParser
from collections import defaultdict
import re
from pybincat.tools import parsers
from pybincat import PyBinCATException
import tempfile
import functools


class PyBinCATParseError(PyBinCATException):
    pass


class Program(object):
    re_val = re.compile("\((?P<region>[^,]+)\s*,\s*(?P<value>[x0-9a-fA-F_,=? ]+)\)")

    def __init__(self, states, edges, nodes):
        #: Value (address) -> State
        self.states = states
        #: nodeid -> list of nodeid (string)
        self.edges = edges
        #: nodes_id -> address
        self.nodes = nodes
        self.logs = None

    @classmethod
    def parse(cls, filename, logs=None):

        states = {}
        edges = defaultdict(list)
        nodes = {}

        config = ConfigParser.ConfigParser()
        config.read(filename)

        for section in config.sections():
            if section == 'edges':
                for edgename, edge in config.items(section):
                    src, dst = edge.split(' -> ')
                    edges[src].append(dst)
                continue
            elif section.startswith('address = '):
                m = cls.re_val.match(section[10:])
                if m:
                    address = Value(m.group("region"), int(m.group("value"), 0))
                    state = State.parse(address, config.items(section))
                    states[address] = state
                    nodes[state.node_id] = address
                    continue
            raise PyBinCATException("Cannot parse section name (%r)" % section)

        program = cls(states, edges, nodes)
        if logs:
            program.logs = open(logs).read()
        return program

    @classmethod
    def from_analysis(cls, initfname):
        """
        Runs analysis from provided init file
        """
        outfile = tempfile.NamedTemporaryFile()
        logfile = tempfile.NamedTemporaryFile()

        return cls.from_filenames(initfname, outfile.name, logfile.name)

    @classmethod
    def from_state(cls, state):
        """
        Runs analysis.
        """
        initfile = tempfile.NamedTemporaryFile()
        initfile.write(str(state))
        initfile.close()

        return cls.from_analysis(initfile.name)

    @classmethod
    def from_filenames(cls, initfname, outfname, logfname):
        """
        Runs analysis, using provided filenames.

        :param initfname: string, path to init file
        :param outfname: string, path to output file
        :param logfname: string, path to log file
        """
        from pybincat import mlbincat
        mlbincat.process(initfname, outfname, logfname)
        return Program.parse(outfname, logs=logfname)

    def _toValue(self, eip):
        if type(eip) in [int, long]:
            addr = Value("global", eip)
        elif type(eip) is Value:
            addr = eip
        elif type(eip) is str:
            addr = Value("global", int(eip))
        # else:
        #     logging.error(
        #         "Invalid address %s (type %s) in AnalyzerState._toValue",
        #         eip, type(eip))
        #     addr = None
        return addr

    def __getitem__(self, pc):
        """
        Returns state at provided PC if it exists, else None.

        :param eip: int, str or Value
        """
        ptr = self._toValue(pc)
        return self.states.get(ptr, None)

    def next_states(self, pc):
        node = self[pc].node_id
        return [self[self.nodes[nn]] for nn in self.edges.get(node, [])]


class State(object):
    def __init__(self, address, node_id=None):
        self.address = address
        self.node_id = node_id
        #: Value -> Value
        self.regaddrs = {}

    @classmethod
    def parse(cls, address, outputkv):
        """
        :param outputkv: list of (key, value) tuples for each property set by
            the analyzer at this EIP
        """

        new_state = State(address)

        for i, (k, v) in enumerate(outputkv):
            if k == "id":
                new_state.node_id = str(v)
                continue
            m = cls.re_region.match(k)
            if not m:
                raise PyBinCATException("Parsing error (entry %i, key=%r)" % (i, k))
            region = m.group("region")
            adrs = m.group("adrs")
            if region == 'mem' and adrs.startswith('(') and adrs.endswith(')'):
                # ex. "(region, 0xabcd)"
                # region in ['stack', 'global', 'heap', stack'
                region, adrs = adrs[1:-1].split(', ')

            m = cls.re_valtaint.match(v)
            if not m:
                raise PyBinCATException("Parsing error (entry %i: value=%r)" % (i, v))
            kind = m.group("kind")
            val = m.group("value")
            taint = m.group("taint")

            regaddr = Value.parse(region, adrs, '0')
            new_state[regaddr] = Value.parse(kind, val, taint)
        return new_state

    def __getitem__(self, item):
        return self.regaddrs[item]

    def __setitem__(self, item, val):
        self.regaddrs[item] = val

    def __getattr__(self, attr):
        if attr.startswith('__'):  # avoid failure in copy.deepcopy()
            raise AttributeError(attr)
        try:
            return self.regaddrs[attr]
        except KeyError:
            raise AttributeError(attr)

    re_region = re.compile("(?P<region>reg|mem)\s*\[(?P<adrs>[^]]+)\]")
    re_valtaint = re.compile("\((?P<kind>[^,]+)\s*,\s*(?P<value>[x0-9a-fA-F_,=? ]+)\s*(!\s*(?P<taint>[x0-9a-fA-F_,=? ]+))?.*\).*")

    def __eq__(self, other):
        if set(self.regaddrs.keys()) != set(other.regaddrs.keys()):
            return False
        for regaddr in self.regaddrs.keys():
            if self.regaddrs[regaddr] != other.regaddrs[regaddr]:
                return False
        return True

    def list_modified_keys(self, other):
        """
        Returns a set of (region, name) for which value or tainting
        differ between self and other.
        """
        # List keys present in only one of the states
        sRA = set(self.regaddrs)
        oRA = set(other.regaddrs)
        results = sRA.symmetric_difference(oRA)
        # Check values
        for regaddr in sRA & oRA:
            if self[regaddr] != other[regaddr]:
                results.add(regaddr)
        return results

    def diff(self, other, pns="", pno=""):
        """
        :param pns: pretty name for self
        :param pno: pretty name for other
        """
        pns += str(self)
        pno += str(other)
        res = ["--- %s" % pns, "+++ %s" % pno]
        for regaddr in self.list_modified_keys(other):
            region = regaddr.region
            address = regaddr.value
            if regaddr.is_concrete() and isinstance(address, int):
                address = "%#08x" % address
            res.append("@@ %s %s @@" % (region, address))
            if regaddr not in self.regaddrs:
                res.append("+ %s" % other.regaddrs[regaddr])
            elif regaddr not in other.regaddrs:
                res.append("- %s" % self.regaddrs[regaddr])
            elif self.regaddrs[regaddr] != other.regaddrs[regaddr]:
                res.append("- %s" % self.regaddrs[regaddr])
                res.append("+ %s" % other.regaddrs[regaddr])
        return "\n".join(res)

    def __repr__(self):
        return "State at address %s" % self.address


@functools.total_ordering
class Value(object):
    def __init__(self, region, value, vtop=0, vbot=0, taint=0, ttop=0, tbot=0):
        self.region = region.lower()
        self.value = value
        self.vtop = vtop
        self.vbot = vbot
        self.taint = taint
        self.ttop = ttop
        self.tbot = tbot

    @classmethod
    def parse(cls, region, s, t):
        value, vtop, vbot = parsers.parse_val(s)
        taint, ttop, tbot = parsers.parse_val(t) if t is not None else (0, 0, 0)
        return cls(region, value, vtop, vbot, taint, ttop, tbot)

    def __repr__(self):
        return "Value(%s, %s ! %s)" % (
            self.region,
            self.__valuerepr__(),
            self.__taintrepr__())

    def __valuerepr__(self):
        return parsers.val2str(self.value, self.vtop, self.vbot)

    def __taintrepr__(self):
        return parsers.val2str(self.taint, self.ttop, self.tbot)

    def __hash__(self):
        return hash((type(self), self.region, self.value,
                     self.vtop, self.vbot, self.taint,
                     self.ttop, self.tbot))

    def __eq__(self, other):
        return (self.region == other.region and
                self.value == other.value and self.taint == other.taint and
                self.vtop == other.vtop and self.ttop == other.ttop and
                self.vbot == other.vbot and self.tbot == other.tbot)

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        return (self.region, self.value) < (other.region, other.value)

    def __add__(self, other):
        other = getattr(other, "value", other)
        return self.__class__(self.region, self.value+other,
                              self.vtop, self.vbot, self.taint,
                              self.ttop, self.tbot)

    def __sub__(self, other):
        other = getattr(other, "value", other)
        return self.__class__(self.region, self.value-other,
                              self.vtop, self.vbot, self.taint,
                              self.ttop, self.tbot)

    def __iand__(self, other):
        other = getattr(other, "value", other)
        self.value &= other
        return self

    def __ior__(self, other):
        other = getattr(other, "value", other)
        self.value |= other
        return self

    def is_concrete(self):
        return self.vtop == 0 and self.vbot == 0
