
import ConfigParser
from collections import defaultdict
import re
from pybincat.tools import parsers
from pybincat import PyBinCATException
import tempfile
import functools


def reg_len(regname):
    """
    Return length in bits
    """
    # register list from decoder.ml
    if regname in ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]:
        return 32
    if regname in ["cs", "ds", "ss", "es", "fs", "gs"]:
        return 16
    if regname in ["cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of", "nt",
                   "rf", "vm", "ac", "vif", "vip", "id"]:
        return 1
    if regname == "iopl":
        return 2


class PyBinCATParseError(PyBinCATException):
    pass


class CFA(object):
    """
    Holds State for each defined node_id.
    Several node_ids may share the same address (ex. loops, partitions)
    """

    def __init__(self, states, edges, nodes):
        #: Value (address) -> [node_id]. Nodes marked "final" come first.
        self.states = states
        #: node_id (string) -> list of node_id (string)
        self.edges = edges
        #: node_id (string) -> State
        self.nodes = nodes
        self.logs = None

    @classmethod
    def parse(cls, filename, logs=None):

        states = defaultdict(list)
        edges = defaultdict(list)
        nodes = {}

        config = ConfigParser.RawConfigParser()
        try:
            config.read(filename)
        except ConfigParser.ParsingError:
            return None
        if len(config.sections()) == 0:
            return None

        for section in config.sections():
            if section == 'edges':
                for edgename, edge in config.items(section):
                    src, dst = edge.split(' -> ')
                    edges[src].append(dst)
                continue
            elif section.startswith('node = '):
                node_id = section[7:]
                state = State.parse(node_id, config.items(section))
                address = state.address
                if state.final:
                    states[address].insert(0, state.node_id)
                else:
                    states[address].append(state.node_id)
                nodes[state.node_id] = state
                continue
            raise PyBinCATException("Cannot parse section name (%r)" % section)

        cfa = cls(states, edges, nodes)
        if logs:
            cfa.logs = open(logs).read()
        return cfa

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
        return cls.parse(outfname, logs=logfname)

    def _toValue(self, eip, region="global"):
        if type(eip) in [int, long]:
            addr = Value(region, eip, 0)
        elif type(eip) is Value:
            addr = eip
        elif type(eip) is str:
            addr = Value(region, int(eip), 0)
        # else:
        #     logging.error(
        #         "Invalid address %s (type %s) in AnalyzerState._toValue",
        #         eip, type(eip))
        #     addr = None
        return addr

    def __getitem__(self, node_id):
        """
        Returns State at provided node_ids if it exists, else None.
        """
        return self.nodes.get(node_id, None)

    def node_id_from_addr(self, addr):
        addr = self._toValue(addr)
        return self.states[addr]

    def next_states(self, node_id):
        """
        Returns a list of State
        """
        return [self[n] for n in self.edges[node_id]]


class State(object):
    re_val = re.compile("\((?P<region>[^,]+)\s*,\s*(?P<value>[x0-9a-fA-F_,=? ]+)\)")
    re_region = re.compile("(?P<region>reg|mem)\s*\[(?P<adrs>[^]]+)\]")
    re_valtaint = re.compile("\((?P<kind>[^,]+)\s*,\s*(?P<value>[x0-9a-fA-F_,=? ]+)\s*(!\s*(?P<taint>[x0-9a-fA-F_,=? ]+))?.*\).*")

    def __init__(self, node_id, address=None):
        self.address = address
        self.node_id = node_id
        #: Value -> Value
        self.regaddrs = {}
        self.final = False
        self.statements = ""
        self.bytes = ""

    @classmethod
    def parse(cls, node_id, outputkv):
        """
        :param outputkv: list of (key, value) tuples for each property set by
            the analyzer at this EIP
        """

        new_state = State(node_id)

        for i, (k, v) in enumerate(outputkv):
            if k == "address":
                m = cls.re_val.match(v)
                if m:
                    address = Value(m.group("region"),
                                    int(m.group("value"), 0), 0)
                    new_state.address = address
                    continue
            if k == "final":
                new_state.final = True if v == 'true' else False
                continue
            if k == "statements":
                new_state.statements = v
                continue
            if k == "bytes":
                new_state.bytes = v
                continue
            m = cls.re_region.match(k)
            if not m:
                raise PyBinCATException("Parsing error (entry %i, key=%r)" % (i, k))
            region = m.group("region")
            adrs = m.group("adrs")
            if region == 'mem':
                # ex. "(region, 0xabcd), (region, 0xabce)"
                # region in ['stack', 'global', 'heap']
                adr_begin, adr_end = adrs[1:-1].split('), (')
                region1, adrs = adr_begin.split(', ')
                region2, adr2 = adr_end.split(', ')
                assert region1 == region2
                region = region1
                length = (parsers.parse_val(adr2)[0] -
                          parsers.parse_val(adrs)[0]) * 8
                # XXX allow non-aligned access
            elif region == 'reg':
                length = reg_len(adrs)

            m = cls.re_valtaint.match(v)
            if not m:
                raise PyBinCATException("Parsing error (entry %i: value=%r)" % (i, v))
            kind = m.group("kind")
            val = m.group("value")
            taint = m.group("taint")

            regaddr = Value.parse(region, adrs, '0', 0)
            new_state[regaddr] = Value.parse(kind, val, taint, length)
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

    def diff(self, other, pns="", pno="", parent=None):
        """
        :param pns: pretty name for self
        :param pno: pretty name for other
        """
        pns += str(self)
        pno += str(other)
        res = ["--- %s" % pns, "+++ %s" % pno]
        if parent:
            res.append("000 Parent %s" % str(parent))
        for regaddr in self.list_modified_keys(other):
            region = regaddr.region
            address = regaddr.value
            if regaddr.is_concrete() and isinstance(address, int):
                address = "%#08x" % address
            res.append("@@ %s %s @@" % (region, address))
            if (parent is not None) and (regaddr in parent.regaddrs):
                res.append("0 %s" % parent.regaddrs[regaddr])
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
    def __init__(self, region, value, length, vtop=0, vbot=0, taint=0, ttop=0,
                 tbot=0):
        self.region = region.lower()
        self.value = value
        self.length = length
        self.vtop = vtop
        self.vbot = vbot
        self.taint = taint
        self.ttop = ttop
        self.tbot = tbot

    @classmethod
    def parse(cls, region, s, t, length):
        value, vtop, vbot = parsers.parse_val(s)
        taint, ttop, tbot = parsers.parse_val(t) if t is not None else (0, 0, 0)
        return cls(region, value, length, vtop, vbot, taint, ttop, tbot)

    def __len__(self):
        return self.length

    def __repr__(self):
        return "Value(%s, %s ! %s)" % (
            self.region,
            self.__valuerepr__(),
            self.__taintrepr__())

    def __valuerepr__(self):
        return parsers.val2str(self.value, self.vtop, self.vbot, self.length)

    def __taintrepr__(self):
        return parsers.val2str(self.taint, self.ttop, self.tbot, self.length)

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
        newvalue = self.value-other
        # XXX clear value where top or bottom mask is not null
        # XXX complete implementation
        return self.__class__(self.region, newvalue,
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
