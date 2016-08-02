# -*- coding: utf-8 -*-
# version IDA 6.9
# runs the "bincat" command from ida

import os
import sys
import traceback
import tempfile
import ConfigParser
import logging
import idaapi
import idabincat.netnode
from idabincat.analyzer_conf import AnalyzerConfig
from idabincat.gui import GUI

from PyQt5 import QtCore
# used in idaapi
from PyQt5 import QtWidgets

# Logging
logging.basicConfig(level=logging.DEBUG)
bc_log = logging.getLogger('bincat.plugin')
bc_log.setLevel(logging.DEBUG)


class BincatPlugin(idaapi.plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "BinCAT"
    wanted_hotkey = "Ctrl-Shift-B"
    comment = "Interface to the BinCAT analyzer"
    help = ""
    initialized = False

    def __init__(self):
        super(BincatPlugin, self).__init__()
        self.state = None

    # IDA API methods: init, run, term
    def init(self):
        try:
            from pybincat import cfa as cfa_module
            global cfa_module
        except:
            bc_log.warning(
                "Failed to load 'pybincat.cfa' python module\n%s",
                repr(sys.exc_info()))
            return idaapi.PLUGIN_SKIP
        self.state = State()
        bc_log.info("IDABinCAT ready.")

        if self.state.options.get("options", "autostart") == "True":
            bc_log.info("Autostarting")
            return idaapi.PLUGIN_KEEP
        else:
            return idaapi.PLUGIN_OK

    def run(self, args):
        if self.initialized:
            return
        self.initialized = True


    def term(self):
        if self.state:
            self.state.clear_background()
            self.state.gui.term()


class Analyzer(QtCore.QProcess):
    """
    Class Analyzer that inherits from Qprocess

    The idea is to implement callbacks on main Qprocess signals
    """

    def __init__(self, initfname, outfname, logfname, finish_cb):
        QtCore.QProcess.__init__(self)
        # Qprocess signal handlers
        self.error.connect(self.procanalyzer_on_error)
        self.stateChanged.connect(self.procanalyzer_on_state_change)
        self.started.connect(self.procanalyzer_on_start)
        self.finished.connect(self.procanalyzer_on_finish)

        self.initfname = initfname
        self.outfname = outfname
        self.logfname = logfname
        self.finish_cb = finish_cb

    def run(self):
        cmdline = "bincat %s %s %s" % (self.initfname, self.outfname,
                                       self.logfname)
        # start the process
        bc_log.debug("Analyzer cmdline: [%s]", cmdline)
        try:
            self.start(cmdline)
        except Exception as e:
            bc_log.error("BinCAT failed to launch the analyzer.py")
            bc_log.warning("Exception: %s\n%s", str(e), traceback.format_exc())
        else:
            bc_log.info("Analyzer started.")

    def procanalyzer_on_error(self, err):
        errors = ["Failed to start", "Crashed", "TimedOut", "Read Error",
                  "Write Error", "Unknown Error"]
        try:
            errtxt = errors[err]
        except IndexError:
            errtxt = "Unspecified error %s" % err
        bc_log.error("Analyzer error: %s", errtxt)
        self.process_output()

    def procanalyzer_on_state_change(self, new_state):
        states = ["Not running", "Starting", "Running"]
        bc_log.debug("Analyzer new state: %s", states[new_state])

    def procanalyzer_on_start(self):
        bc_log.info("Analyzer: starting process")

    def procanalyzer_on_finish(self):
        bc_log.info("Analyzer process finished")
        exitcode = self.exitCode()
        bc_log.error("analyzer returned exit code=%i", exitcode)
        self.process_output()

    def process_output(self):
        """
        Try to process analyzer output.
        """
        bc_log.info("---- stdout ----------------")
        bc_log.info(str(self.readAllStandardOutput()))
        bc_log.info("---- stderr ----------------")
        bc_log.info(str(self.readAllStandardError()))
        bc_log.debug("---- logfile ---------------")
        if os.path.exists(self.logfname):
            bc_log.debug(open(self.logfname).read())
        bc_log.debug("----------------------------")
        self.finish_cb(self.outfname, self.logfname)


class State(object):
    """
    Container for (static) plugin state related data & methods.
    """
    def __init__(self):
        self.current_ea = None
        self.cfa = None
        self.current_state = None
        # Configuration files path
        idausr = os.getenv('IDAUSR')
        if not idausr:
            idausr = os.path.join(os.getenv("HOME"), ".idapro")
            bc_log.warning("IDAUSR not defined, using %s", idausr)
        self.config_path = os.path.join(idausr, "idabincat")
        self.current_config = AnalyzerConfig()
        #: Analyzer instance
        self.analyzer = None
        self.hooks = None
        self.gui = GUI(self)
        self.netnode = idabincat.netnode.Netnode("$ com.bincat.bcplugin")
        self.load_from_idb()

        # Plugin options
        def_options = {'save_to_idb': "False", "load_from_idb": "True", "autostart": "False"}
        self.options = ConfigParser.ConfigParser(defaults=def_options)
        self.options.optionxform = str
        configfile = os.path.join(self.config_path, "conf", "options.ini")
        if len(self.options.read(configfile)) != 1:
            self.options.add_section("options")

    # Save current options to file
    def save_options(self):
        optfile = open(os.path.join(self.config_path, "conf", "options.ini"), "w")
        self.options.write(optfile)
        optfile.close()

    def load_from_idb(self):
        if "out.ini" in self.netnode and "analyzer.log" in self.netnode:
            bc_log.info("Loading analysis results from idb")
            path = tempfile.mkdtemp(suffix='bincat')
            outfname = os.path.join(path, "out.ini")
            logfname = os.path.join(path, "analyzer.log")
            with open(outfname, 'w') as outfp:
                outfp.write(self.netnode["out.ini"])
            with open(logfname, 'w') as logfp:
                logfp.write(self.netnode["analyzer.log"])
            if "current_ea" in self.netnode:
                ea = self.netnode["current_ea"]
            else:
                ea = None
            self.analysis_finish_cb(outfname, logfname, ea)

    def clear_background(self):
        """
        reset background color for previous analysis
        """
        if self.cfa:
            color = idaapi.calc_bg_color(idaapi.NIF_BG_COLOR)
            for v in self.cfa.states:
                ea = v.value
                idaapi.set_item_color(ea, color)

    def analysis_finish_cb(self, outfname, logfname, ea=None):
        bc_log.debug("Parsing analyzer result file")
        cfa = cfa_module.CFA.parse(outfname, logs=logfname)
        self.clear_background()
        if cfa:
            self.cfa = cfa
            # XXX add user preference for saving to idb?
            bc_log.info("Storing analysis results to idb")
            self.netnode["out.ini"] = open(outfname).read()
            self.netnode["analyzer.log"] = open(logfname).read()
        else:
            bc_log.info("Empty result file.")
        bc_log.debug("----------------------------")
        # Update current RVA to start address (nodeid = 0)
        if ea is not None:
            current_ea = ea
        else:
            node0 = cfa['0']
            current_ea = node0.address.value
        self.set_current_ea(current_ea, force=True)
        for v in cfa.states:
            ea = v.value
            idaapi.set_item_color(ea, 0xCDCFCE)
        self.netnode["current_ea"] = current_ea

    def set_current_ea(self, ea, force=False):
        """
        :param ea: int or long
        """
        if not (force or ea != self.current_ea):
            return
        self.gui.before_change_ea()
        self.current_ea = ea
        if self.cfa:
            node_ids = self.cfa.node_id_from_addr(ea)
            if node_ids:
                # XXX add UI to choose state when several exist at this address
                self.current_state = self.cfa[node_ids[0]]
            else:
                self.current_state = None
        self.gui.after_change_ea()

    def start_analysis(self, config_str=None):
        path = tempfile.mkdtemp(suffix='bincat')
        initfname = os.path.join(path, "init.ini")
        outfname = os.path.join(path, "out.ini")
        logfname = os.path.join(path, "analyzer.log")

        bc_log.debug("Current analyzer path: %s", path)

        if config_str:
            with open(initfname, 'wb') as f:
                f.write(config_str)
        else:
            self.current_config.write(initfname)

        self.analyzer = Analyzer(initfname, outfname, logfname,
                                 self.analysis_finish_cb)
        self.analyzer.run()


def PLUGIN_ENTRY():
    return BincatPlugin()
