"""
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
"""

import subprocess
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
from collections import defaultdict
import re
from pybincat.tools import parsers
from pybincat import PyBinCATException
import tempfile
import functools
# Python 2/3 compat
import sys
if sys.version_info > (2, 8):
    long = int

def reg_len(regname):
    """
    Returns register length in bits. CFA.arch must have been set, either
    manually or by parsing a bincat output file.
    """
    if CFA.arch == "armv8":
        return {
            "x0": 64, "x1": 64, "x2": 64, "x3": 64, "x4": 64, "x5": 64,
            "x6": 64, "x7": 64, "x8": 64, "x9": 64, "x10": 64, "x11": 64,
            "x12": 64, "x13": 64, "x14": 64, "x15": 64, "x16": 64, "x17": 64,
            "x18": 64, "x19": 64, "x20": 64, "x21": 64, "x22": 64, "x23": 64,
            "x24": 64, "x25": 64, "x26": 64, "x27": 64, "x28": 64, "x29": 64,
            "x30": 64, "sp": 64,
            "q0": 128, "q1": 128, "q2": 128, "q3": 128, "q4": 128, "q5": 128,
            "q6": 128, "q7": 128, "q8": 128, "q9": 128, "q10": 128, "q11": 128,
            "q12": 128, "q13": 128, "q14": 128, "q15": 128, "q16": 128,
            "q17": 128, "q18": 128, "q19": 128, "q20": 128, "q21": 128,
            "q22": 128, "q23": 128, "q24": 128, "q25": 128, "q26": 128,
            "q27": 128, "q28": 128, "q29": 128, "q30": 128, "q31": 128,
            "pc": 64, "xzr": 64, "c": 1, "n": 1, "v": 1, "z": 1}[regname]
    elif CFA.arch == "armv7":
        return {
            "r0": 32, "r1": 32, "r2": 32, "r3": 32, "r4": 32, "r5": 32,
            "r6": 32, "r7": 32, "r8": 32, "r9": 32, "r10": 32, "r11": 32,
            "r12": 32, "sp": 32, "lr": 32, "pc": 32, "itstate": 8,
            "c": 1, "n": 1, "v": 1, "z": 1, "t": 1}[regname]
    elif CFA.arch == "x64":
        return {
            "rax": 64, "rbx": 64, "rcx": 64, "rdx": 64,
            "rsi": 64, "rdi": 64, "rsp": 64, "rbp": 64,
            "r8": 64, "r9": 64, "r10": 64, "r11": 64,
            "r12": 64, "r13": 64, "r14": 64, "r15": 64, "rip": 64,
            "eax": 32, "ebx": 32, "ecx": 32, "edx": 32,
            "esi": 32, "edi": 32, "esp": 32, "ebp": 32,
            "ax": 16, "bx": 16, "cx": 16, "dx": 16, "si": 16, "di": 16,
            "sp": 16, "bp": 16, "cs": 16, "ds": 16, "es": 16, "ss": 16,
            "fs": 16, "gs": 16, "fs_base": 64, "gs_base": 64,
            "iopl": 2,
            "mxcsr_fz": 1, "mxcsr_round": 2, "mxcsr_pm": 1, "mxcsr_um": 1,
            "mxcsr_om": 1, "mxcsr_zm": 1, "mxcsr_dm": 1, "mxcsr_im": 1,
            "mxcsr_daz": 1, "mxcsr_pe": 1, "mxcsr_ue": 1, "mxcsr_oe": 1,
            "mxcsr_ze": 1, "mxcsr_de": 1, "mxcsr_ie": 1,
            "xmm0": 128, "xmm1": 128, "xmm2": 128, "xmm3": 128,
            "xmm4": 128, "xmm5": 128, "xmm6": 128, "xmm7": 128,
            "xmm8": 128, "xmm9": 128, "xmm10": 128, "xmm11": 128,
            "xmm12": 128, "xmm13": 128, "xmm14": 128, "xmm15": 128,
            "st_ptr": 3, "c0": 1, "c1": 1, "c2": 1, "c3": 1,
            "cf": 1, "pf": 1, "af": 1, "zf": 1, "sf": 1, "tf": 1, "if": 1,
            "df": 1, "of": 1, "nt": 1, "rf": 1, "vm": 1, "ac": 1, "vif": 1,
            "vip": 1, "id": 1}[regname]
    elif CFA.arch == "x86":
        return {
            "eax": 32, "ebx": 32, "ecx": 32, "edx": 32,
            "esi": 32, "edi": 32, "esp": 32, "ebp": 32,
            "ax": 16, "bx": 16, "cx": 16, "dx": 16, "si": 16, "di": 16,
            "sp": 16, "bp": 16, "cs": 16, "ds": 16, "es": 16, "ss": 16,
            "fs": 16, "gs": 16,
            "iopl": 2,
            "mxcsr_fz": 1, "mxcsr_round": 2, "mxcsr_pm": 1, "mxcsr_um": 1,
            "mxcsr_om": 1, "mxcsr_zm": 1, "mxcsr_dm": 1, "mxcsr_im": 1,
            "mxcsr_daz": 1, "mxcsr_pe": 1, "mxcsr_ue": 1, "mxcsr_oe": 1,
            "mxcsr_ze": 1, "mxcsr_de": 1, "mxcsr_ie": 1,
            "xmm0": 128, "xmm1": 128, "xmm2": 128, "xmm3": 128,
            "xmm4": 128, "xmm5": 128, "xmm6": 128, "xmm7": 128,
            "st_ptr": 3, "c0": 1, "c1": 1, "c2": 1, "c3": 1,
            "cf": 1, "pf": 1, "af": 1, "zf": 1, "sf": 1, "tf": 1, "if": 1,
            "df": 1, "of": 1, "nt": 1, "rf": 1, "vm": 1, "ac": 1, "vif": 1,
            "vip": 1, "id": 1}[regname]
    elif CFA.arch == "powerpc":
        return {
            "r0": 32, "r1": 32, "r2": 32, "r3": 32, "r4": 32, "r5": 32,
            "r6": 32, "r7": 32, "r8": 32, "r9": 32, "r10": 32, "r11": 32,
            "r12": 32, "r13": 32, "r14": 32, "r15": 32, "r16": 32, "r17": 32,
            "r18": 32, "r19": 32, "r20": 32, "r21": 32, "r22": 32, "r23": 32,
            "r24": 32, "r25": 32, "r26": 32, "r27": 32, "r28": 32, "r29": 32,
            "r30": 32, "r31": 32, "lr": 32, "ctr": 32, "cr": 32,
            "tbc": 7, "so": 1, "ov": 1, "ca": 1}[regname]
    elif CFA.arch.lower() == "rv32i":
        return {
            "x0": 32, "x1": 32, "x2": 32, "x3": 32, "x4": 32, "x5": 32,
            "x6": 32, "x7": 32, "x8": 32, "x9": 32, "x10": 32, "x11": 32,
            "x12": 32, "x13": 32, "x14": 32, "x15": 32, "x16": 32, "x17": 32,
            "x18": 32, "x19": 32, "x20": 32, "x21": 32, "x22": 32, "x23": 32,
            "x24": 32, "x25": 32, "x26": 32, "x27": 32, "x28": 32, "x29": 32,
            "x30": 32, "x31": 32 }[regname]
    elif CFA.arch.lower() == "rv64i":
        return {
            "x0": 64, "x1": 64, "x2": 64, "x3": 64, "x4": 64, "x5": 64,
            "x6": 64, "x7": 64, "x8": 64, "x9": 64, "x10": 64, "x11": 64,
            "x12": 64, "x13": 64, "x14": 64, "x15": 64, "x16": 64, "x17": 64,
            "x18": 64, "x19": 64, "x20": 64, "x21": 64, "x22": 64, "x23": 64,
            "x24": 64, "x25": 64, "x26": 64, "x27": 64, "x28": 64, "x29": 64,
            "x30": 64, "x31": 64 }[regname]
    else:
        raise KeyError("Unknown arch %s" % CFA.arch)


#: maps short region names to pretty names
PRETTY_REGIONS = {'': 'global', 'h': 'heap',
                  'b': 'bottom', 't': 'top'}  # used for pointers only

#: split src region + address (left of '=')
RE_REGION_ADDR = re.compile(r"(?P<region>reg|mem|h[0-9]+)\[(?P<addr>[^]]+)\]")
#: split value

RE_VALTAINT = re.compile(
    r"(?P<memreg>([a-zA-Z]?|[hH]\d+))-?(?P<value>0[xb][0-9a-fA-F_?]+)(!(?P<taint>\S+)|)?")

RE_NODE_UNREL = re.compile(
    r"node (?P<nodeid>\d+) - unrel (?P<unrelid>\d+)")


class PyBinCATParseError(PyBinCATException):
    pass


class CFA(object):
    """
    Holds Node for each defined node_id.
    Several node_ids may share the same address (ex. loops, partitions)
    """
    #: Cache to speed up value parsing. (str, length) -> [Value, ...]
    _valcache = {}
    arch = None

    def __init__(self, addr_nodes, edges, nodes, taintsrcs):
        #: Value (address) -> [node_id]. Nodes marked "final" come first.
        self.addr_nodes = addr_nodes
        #: node_id (string) -> list of node_id (string)
        self.edges = edges
        #: node_id (string) -> Node
        self.nodes = nodes
        self.logs = None
        #: taint source id (int) -> taint source (str)
        self.taintsrcs = taintsrcs

    @classmethod
    def parse(cls, filename, logs=None):

        addr_nodes = defaultdict(list)
        edges = defaultdict(list)
        nodes = {}
        taintsrcs = {}
        cfa = cls(addr_nodes, edges, nodes, taintsrcs)

        config = ConfigParser.RawConfigParser()
        try:
            config.read(filename)
        except ConfigParser.ParsingError as e:
            estr = str(e)
            if len(estr) > 400:
                estr = estr[:200] + '\n...\n' + estr[-200:]
            raise PyBinCATException(
                "Invalid INI format for parsed output file %s.\n%s" %
                (filename, estr))
        if len(config.sections()) == 0:
            raise PyBinCATException(
                "Parsing error: no sections in %s, check analysis logs" %
                filename)

        cls.arch = config.get('program', 'architecture')
        cls.mem_sz = config.get('program', 'mem_sz')
        # parse taint sources first -- will be used when parsing Node
        # sorting ensures that a node will be parsed before its unrels
        sections = sorted(config.sections(), reverse=True)
        if 'taint sources' in config.sections():
            for srcid, srcname in config.items('taint sources'):
                taintsrcs[int(srcid)] = srcname
            sections.remove('taint sources')
            maxtaintsrcid = max(list(taintsrcs)+[0])
        for section in sections:
            if section == 'edges':
                for edgename, edge in config.items(section):
                    src, dst = edge.split(' -> ')
                    edges[src].append(dst)
                continue
            elif section.startswith('node = '):
                node_id = section[7:]
                node = Node.parse(node_id, dict(config.items(section)),
                                  maxtaintsrcid)
                address = node.address
                if node.final:
                    addr_nodes[address].insert(0, node.node_id)
                else:
                    addr_nodes[address].append(node.node_id)
                nodes[node.node_id] = node
                continue
            elif section.startswith('node '):
                m = RE_NODE_UNREL.match(section)
                unrel_id = m.group('unrelid')
                new_unrel = Unrel.parse(unrel_id, dict(config.items(section)))
                cfa[m.group('nodeid')].unrels[unrel_id] = new_unrel
                # unrel
            elif section == 'loader':
                continue

        CFA._valcache = dict()
        if logs:
            cfa.logs = open(logs, 'rb').read()
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
    def from_filenames(cls, initfname, outfname, logfname):
        """
        Runs analysis, using provided filenames.

        :param initfname: string, path to init file
        :param outfname: string, path to output file
        :param logfname: string, path to log file
        """
        try:
            from pybincat import mlbincat
            mlbincat.process(initfname, outfname, logfname)
        except ImportError:
            # XXX log warning
            subprocess.call(["bincat", initfname, outfname, logfname])
        return cls.parse(outfname, logs=logfname)

    def _toValue(self, eip, region=""):
        if isinstance(eip, (int, long)):
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
        Returns Node at provided node_id if it exists, else None.
        """
        if type(node_id) is int:
            node_id = str(node_id)
        return self.nodes.get(node_id, None)

    def node_id_from_addr(self, addr):
        addr = self._toValue(addr)
        return self.addr_nodes[addr]

    def next_nodes(self, node_id):
        """
        Returns a list of Node
        """
        return [self[n] for n in self.edges[str(node_id)]]


class Node(object):
    """
    Stores node data for a given node_id.

    1 or more Unrel may be stored, each containg regaddrs, regtypes
    """
    __slots__ = ['address', 'node_id', 'final', 'statements', 'bytes',
                 'tainted', 'taintsrc', 'unrels']

    def __init__(self, node_id, address=None, lazy_init=None):
        self.address = address
        #: str
        self.node_id = node_id
        #: str (unrel id) -> Unrel
        self.unrels = {}
        self.final = False
        self.statements = ""
        self.bytes = ""
        self.tainted = False
        #: list of taint id (int)
        self.taintsrc = []

    @classmethod
    def parse(cls, node_id, outputkv, maxtaintsrcid):
        """
        :param outputkv: list of (key, value) tuples for each property set by
            the analyzer at this EIP
        """

        new_node = Node(node_id)
        addr = outputkv.pop("address")
        m = RE_VALTAINT.match(addr)
        new_node.address = Value(m.group("memreg"),
                                 int(m.group("value"), 0), 0)
        new_node.final = outputkv.pop("final", None) == "true"
        new_node.statements = outputkv.pop("statements", "")
        new_node.bytes = outputkv.pop("bytes", "")
        taintedstr = outputkv.pop("tainted", "")
        if taintedstr == "true":
            # v0.6 format
            tainted = True
            taintsrc = ["t-0"]
        elif taintedstr == "" or taintedstr.startswith("?"):  # XXX awaiting bugfix == "?":
            # v0.7+ format, not tainted
            tainted = False
            taintsrc = []
        elif taintedstr.startswith("_"):  # XXX == "_":
            # XXX "tainted=__" should not happen -- awaiting bugfix
            # v1.0 format, tainted = BOT
            tainted = True
            taintsrc = ["t-" + str(maxtaintsrcid)]
        else:
            # v0.7+ format, tainted
            try:
                taintsrc = list(map(unicode.strip, taintedstr.split(',')))
            except NameError:
                taintsrc = list(map(str.strip, taintedstr.split(',')))
            tainted = True
        new_node.tainted = tainted
        new_node.taintsrc = taintsrc
        return new_node

    def default_unrel(self):
        return self.unrels[self.default_unrel_id()]

    def default_unrel_id(self):
        ids = sorted(self.unrels.keys())
        if not ids:
            return None
        return ids[0]

    def __repr__(self):
        return "Node at address %s (node=%s)" % (self.address, self.node_id)


@functools.total_ordering
class Value(object):
    __slots__ = ['vtop', 'vbot', 'taint', 'ttop', 'tbot', 'length', 'value', 'region']

    def __init__(self, region, value, length=None, vtop=0, vbot=0, taint=0,
                 ttop=0, tbot=0):
        self.region = region.lower()
        self.value = value
        if not length and region == 'reg':
            self.length = reg_len(value)
        else:
            self.length = length
        self.vtop = vtop
        self.vbot = vbot
        self.taint = taint
        self.ttop = ttop
        self.tbot = tbot

    @classmethod
    def parse(cls, region, s, t, length):
        region = region.lower()
        value, vtop, vbot = parsers.parse_val(s)
        if type(value) is int and length != 0:
            value &= 2**length-1
            vtop &= 2**length-1
            vbot &= 2**length-1
        if t is None or t == "NONE":
            taint, ttop, tbot = (0, 0, 0)
        elif t == "ALL":
            taint, ttop, tbot = (2**length-1, 0, 0)
        else:
            taint, ttop, tbot = parsers.parse_val(t)
        return cls(region, value, length, vtop, vbot, taint, ttop, tbot)

    @property
    def prettyregion(self):
        return PRETTY_REGIONS.get(self.region, self.region)

    def __len__(self):
        return self.length

    def __repr__(self):
        return "Value(%s, %s ! %s)" % (
            self.region,
            self.__valuerepr__(),
            self.__taintrepr__())

    def __valuerepr__(self, base=None, merged=False):
        return parsers.val2str(self.value, self.vtop, self.vbot, self.length, base, merged)

    def __taintrepr__(self, base=None, merged=False):
        return parsers.val2str(self.taint, self.ttop, self.tbot, self.length, base, merged)

    def __hash__(self):
        return hash((type(self), self.region, self.value,
                     self.vtop, self.vbot, self.taint,
                     self.ttop, self.tbot))

    def __eq__(self, other):
        if type(other) != Value:
            return False
        return (self.region == other.region and
                self.value == other.value and self.taint == other.taint and
                self.vtop == other.vtop and self.ttop == other.ttop and
                self.vbot == other.vbot and self.tbot == other.tbot)

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        return (self.region, self.value) < (other.region, other.value)

    def __add__(self, other):

        newlen = max(self.length, getattr(other, "length", 0))
        other = getattr(other, "value", other)
        if other == 0:
            # special case, useful when the value is a register name
            return self

        mask = (1 << newlen)-1
        newval = self.value + other
        if mask:
            newval = newval & mask
        # XXX clear value where top or bottom mask is not null
        # XXX complete implementation

        return self.__class__(self.region,
                              newval,
                              newlen,
                              self.vtop, self.vbot, self.taint,
                              self.ttop, self.tbot)

    def __and__(self, other):
        """ concatenation """
        if self.region != other.region:
            raise TypeError(
                "Concatenation can only be performed between Value objects "
                "having the same region. %s != %s", self.region, other.region)
        return self.__class__(
            region=self.region,
            value=(self.value << other.length) + other.value,
            length=self.length+other.length,
            vtop=(self.vtop << other.length) + other.vtop,
            vbot=(self.vbot << other.length) + other.vbot,
            taint=(self.taint << other.length) + other.taint,
            ttop=(self.ttop << other.length) + other.ttop,
            tbot=(self.tbot << other.length) + other.tbot,
            )

    def __sub__(self, other):
        newlen = max(self.length, getattr(other, "length", 0))
        other = getattr(other, "value", other)

        mask = (1 << newlen)-1

        newvalue = (self.value-other) & mask
        # XXX clear value where top or bottom mask is not null
        # XXX complete implementation
        return self.__class__(self.region, newvalue, self.length,
                              self.vtop, self.vbot, self.taint,
                              self.ttop, self.tbot)

    def __getitem__(self, idx):
        if type(idx) is slice:
            if idx.step is not None:
                raise TypeError
            start = idx.start
            stop = idx.stop
        else:
            start = idx
            stop = idx + 1
        if start >= self.length or start < 0:
            raise IndexError
        if stop > self.length or stop <= 0:
            raise IndexError
        if stop - start <= 0:
            raise IndexError

        def mask(x):
            return (x >> (8*start)) & (2**(8*(stop-start))-1)

        return Value(self.region,
                     mask(self.value),
                     8*(stop-start),
                     mask(self.vtop),
                     mask(self.vbot),
                     mask(self.taint),
                     mask(self.ttop),
                     mask(self.tbot))

    def is_concrete(self):
        return self.vtop == 0 and self.vbot == 0

    def is_tainted(self):
        return (self.taint != 0 or
                self.ttop != 0 or
                self.tbot != 0)

    def split_to_bytelist(self):
        """
        Return a list of 8-byte long Values, having the same value as self
        """
        result = []

        def mask(x, pos):
            return (x >> pos) & 0xFF

        for i in range(self.length/8):
            result.append(self[i])

        return result


class Unrel(object):
    """
    Contains memory & registers status for a given (Node, unrel_id)

    bincat output format examples:
    reg [eax] = 0xfff488!0
    111  222    33333333333

    mem[0x1234, 0x1236] = 0x20, 0x0
    111 2222222222222222  33333 3333 <-- list of 2 valtaint

    mem[0x24*32] = 0b????1111!0b????0000
    111 22222222   3333333333333333333333 <-- list of 1 valtaint

    1: src region (overridden with src region contained in address for memory)
    2: address
    3: dst region, value, taint (valtaint)

    example valtaints: 0x1234 0x12!0xF0 0x12!ALL
    """
    __slots__ = ['_regaddrs', '_regtypes', '_outputkv', 'unrel_id', 'description']

    def __init__(self, unrel_id):
        #: Value -> [Value]. Either 1 value, or a list of 1-byte Values.
        self._regaddrs = {}
        #: Value -> "type"
        self._regaddrs = None
        self._regtypes = None
        self._outputkv = None
        #: str
        self.unrel_id = unrel_id

    @property
    def regaddrs(self):
        if self._regaddrs is None:
            try:
                self.parse_regaddrs()
            except Exception as e:
                import traceback
                traceback.print_exc(e)
                raise PyBinCATException(
                    "Cannot parse taint or type data at address %s\n%r" %
                    (self.address, e))
        return self._regaddrs

    @property
    def regtypes(self):
        if self._regtypes is None:
            try:
                self.parse_regaddrs()
            except Exception as e:
                import traceback
                traceback.print_exc(e)
                raise PyBinCATException(
                    "Cannot parse taint or type data at address %s\n%s" %
                    (self.address, e))
        return self._regtypes

    @classmethod
    def parse(cls, unrel_id, outputkv):
        new_unrel = Unrel(unrel_id)
        new_unrel._outputkv = outputkv
        return new_unrel

    def parse_regaddrs(self):
        """
        Parses entries containing taint & type data
        """
        self._regaddrs = {}
        self._regtypes = {}
        for k, v in self._outputkv.items():
            if k == "description":
                self.description = k
                continue
            if k.startswith("t-"):
                typedata = True
                k = k[2:]
            else:
                typedata = False

            m = RE_REGION_ADDR.match(k)
            if not m:
                raise PyBinCATException("Parsing error (key=%r)" % (k,))
            region = m.group("region")
            addr = m.group("addr")
            if region == "mem":
                # use memreg as region instead of 'mem'
                # ex. "s0xabcd, s0xabce" "g0x24*32"
                # region = ''
                if '*' in addr:
                    # single repeated value
                    regaddr, repeat = addr.split('*')
                    length = 8
                    m = RE_VALTAINT.match(regaddr)
                    region, addr = m.group('memreg'), m.group('value')
                    v = ', '.join([v] * int(repeat))
                else:
                    regaddr1, regaddr2 = addr.split(', ')
                    m = RE_VALTAINT.match(regaddr1)
                    region1, addr = m.group('memreg'), m.group('value')
                    m = RE_VALTAINT.match(regaddr2)
                    region2, addr2 = m.group('memreg'), m.group('value')
                    assert region1 == region2
                    region = region1
                    length = 8
                    # XXX allow non-aligned access (current: assume no overlap)
            elif region and region[0] == "h":
                # ignore for now -- indicates whether this Heap region has been
                # allocated or freed
                continue
            elif region == "reg":
                length = reg_len(addr)

            # build value
            concat_value = []
            regaddr = Value.parse(region, addr, '0', 0)
            if typedata:
                if regaddr in self._regtypes:
                    self._regtypes[regaddr] += " -- " + v
                else:
                    self._regtypes[regaddr] = v
                continue
            if (v, length) not in CFA._valcache:
                # add to cache
                off_vals = []
                for idx, val in enumerate(v.split(', ')):
                    m = RE_VALTAINT.match(val)
                    if not m:
                        raise PyBinCATException(
                            "Parsing error (value=%r)" % (v,))
                    memreg = m.group("memreg")
                    strval = m.group("value")
                    taint = m.group("taint")
                    new_value = Value.parse(memreg, strval, taint, length)
                    if new_value.region:
                        curregaddr = regaddr + idx
                        regstr = "region " + new_value.region
                        if curregaddr in self._regtypes:
                            self._regtypes[curregaddr] = (
                                regstr + " - " + self._regtypes[curregaddr])
                        else:
                            self._regtypes[curregaddr] = regstr
                    # concatenate
                    concat_value.append(new_value)

                off_vals.append(concat_value)
                CFA._valcache[(v, length)] = off_vals
            for val in CFA._valcache[(v, length)]:
                self._regaddrs[regaddr] = val

        del self._outputkv

    def getregtype(self, item):
        """
        :param item: Value (address)
        Return str
        """
        if type(item) is str:
            # register, used for debugging (ex. human input from IDA)
            item = Value('reg', item, '0', 0)
        if type(item) is not Value:
            raise KeyError
        if item in self.regtypes:
            return self.regtypes[item]

    def __getitem__(self, item):
        """
        Return list of Value
        """
        if type(item) is str:
            # register, used for debugging (ex. human input from IDA)
            item = Value('reg', item, '0', 0)
        if type(item) is not Value:
            raise KeyError
        if item in self.regaddrs:
            return self.regaddrs[item]
        else:
            # looking for address in list of 1-byte Value
            for addr in self.regaddrs:
                if addr.region != item.region:
                    continue
                if item.value < addr.value:
                    continue
                vlist = self.regaddrs[addr]
                if addr.value + len(vlist) > item.value:
                    return vlist[item.value-addr.value:]
            raise IndexError(item)

    def mem_ranges(self):
        """
        Return a dict of regions pointing to a list of tuples
        the tuples indicate the valid memory ranges
        ranges are sorted and coleasced
        """
        ranges = defaultdict(list)
        for addr in list(self.regaddrs.keys()):
            if addr.region != 'reg':
                ranges[addr.region].append((addr.value, addr.value+len(self.regaddrs[addr])-1))
        # Sort ranges
        for region in ranges:
            ranges[region].sort(key=lambda x: x[0])
            # merge
            merged = []
            last_addr = None
            for crange in ranges[region]:
                if last_addr and crange[0] == (last_addr+1):
                    merged[-1] = (merged[-1][0], crange[1])
                else:
                    merged.append(crange)
                last_addr = crange[1]
            ranges[region] = merged
        return ranges

    def get_mem_range(self, region, start, length):
        m = []
        i = start
        while len(m) < length:
            try:
                r = self[Value(region, i)]
            except IndexError:
                i += 1
                m.append(Value(region, 0, vtop=0, vbot=0xff))
            else:
                m += r
                i += len(r)
        m = m[:length]
        value = "".join(chr(v.value) for v in m)
        vtop = "".join(chr(v.vtop) for v in m)
        vbot = "".join(chr(v.vbot) for v in m)
        return value, vtop, vbot

    def get_string(self, region, start):
        m = []
        i = start
        while True:
            r = self[Value(region, i)]
            for v in r:
                if v.vbot or v.vtop:
                    raise LookupError("top or bottom values encountered")
                if v.value == 0:
                    break
                m.append(chr(v.value))
                i += 1
            else:
                continue
            break
        return "".join(m)

    def __setitem__(self, item, val):
        if type(val[0]) is list:
            val = val[0]
        if type(item.value) is str:
            # register, overwrite
            self.regaddrs[item] = val
            return
        if len(val) == 1 and val[0].length > 8:
            val = val[0].split_to_bytelist()
        for (idx, v) in enumerate(val):
            addr = item.value + idx
            recorded = False
            for e_key, e_val in list(self.regaddrs.items()):
                # existing keys in regaddrs
                if type(e_key.value) is str:
                    # e_key is a register, item is a memory address => skip
                    continue
                # e_val: list of Values, or one Value.
                if len(e_val) == 1 and e_val[0].length > 8:
                    if (e_key.value > addr or
                            e_key.value + e_val[0].length < addr):
                        continue
                    # existing value needs to be split, too
                    self.regaddrs[e_key] = e_val[0].split_to_bytelist()
                else:
                    if (e_key.value > addr or
                            e_key.value + len(e_val) < addr):
                        continue
                if len(e_val) == (addr - e_key.value):
                    # appending at the end of existing key e_key
                    self.regaddrs[e_key].append(v)
                    if item+idx+1 in self.regaddrs:
                        # merge with next allocated block
                        self.regaddrs[e_key].extend(self.regaddrs[e_key+idx+1])
                        del self.regaddrs[item+idx+1]
                else:
                    # value replacement in an existing key
                    self.regaddrs[e_key][(addr - e_key.value)] = v
                recorded = True
                break
            if not recorded:
                # new key
                self.regaddrs[item+idx] = [val[idx]]
                if item+idx+1 in self.regaddrs:
                    # merge with next allocated block
                    self.regaddrs[item+idx].extend(self.regaddrs[item+idx+1])
                    del self.regaddrs[item+idx+1]

    def __getattr__(self, attr):
        try:
            return self.regaddrs[attr]
        except KeyError as e:
            raise AttributeError(attr)

    def __eq__(self, other):
        if set(self.regaddrs.keys()) != set(other.regaddrs.keys()):
            return False
        for regaddr in list(self.regaddrs.keys()):
            if ((len(self.regaddrs[regaddr]) > 1) ^
                    (len(other.regaddrs[regaddr]) > 1)):
                # split required, one of them only is split
                s = self.regaddrs[regaddr]
                o = other.regaddrs[regaddr]
                if len(self.regaddrs[regaddr]) == 1:
                    s = s[0].split_to_bytelist()
                else:
                    o = o[0].split_to_bytelist()
                if s != o:
                    return False
            else:
                # no split required
                if self.regaddrs[regaddr] != other.regaddrs[regaddr]:
                    return False
        return True

    def list_modified_keys(self, other):
        """
        Returns a set of (region, name) for which value or tainting
        differ between self and other.
        """
        # List keys present in only one of the nodes
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
            res.insert(0, "000 Parent %s" % str(parent))
        for regaddr in self.list_modified_keys(other):
            region = regaddr.region
            address = regaddr.value
            if regaddr.is_concrete() and isinstance(address, (int, long)):
                address = "%#08x" % address
            res.append("@@ %s %s @@" % (region, address))
            if (parent is not None) and (regaddr in parent.regaddrs):
                res.append("0 %s" % (parent.regaddrs[regaddr]))
            if regaddr not in self.regaddrs:
                res.append("+ %s" % other.regaddrs[regaddr])
            elif regaddr not in other.regaddrs:
                res.append("- %s" % self.regaddrs[regaddr])
            elif self.regaddrs[regaddr] != other.regaddrs[regaddr]:
                res.append("- %s" % (self.regaddrs[regaddr]))
                res.append("+ %s" % (other.regaddrs[regaddr]))
        return "\n".join(res)

