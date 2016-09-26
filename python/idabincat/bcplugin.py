# -*- coding: utf-8 -*-
# version IDA 6.9
# runs the "bincat" command from ida

import ConfigParser
import hashlib
import logging
import os
import re
import StringIO
import sys
import tempfile
import traceback
try:
    import requests
except:
    # log message will be displayed later
    pass
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
        procname = idaapi.get_inf_structure().get_proc_name()
        if procname[0] != 'metapc':
            bc_log.info("Not on x86, not loading BinCAT")
            return idaapi.PLUGIN_SKIP
        try:
            from pybincat import cfa as cfa_module
            global cfa_module
        except:
            bc_log.warning(
                "Failed to load 'pybincat.cfa' python module\n%s",
                repr(sys.exc_info()))
            return idaapi.PLUGIN_SKIP
        options = PluginOptions()
        if options.get("autostart") != "True":
            # will initialize later
            return idaapi.PLUGIN_OK

        bc_log.info("Autostarting")

        self.state = State(options)
        self.initialized = True
        bc_log.info("IDABinCAT ready.")
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        if self.initialized:
            return
        options = PluginOptions()
        self.state = State(options)
        # XXX move
        self.initialized = True
        bc_log.info("IDABinCAT ready.")

    def term(self):
        if self.state:
            self.state.clear_background()
            self.state.gui.term()


class Analyzer(object):
    def __init__(self, path, options, finish_cb):
        self.path = path
        self.options = options
        self.finish_cb = finish_cb

    @property
    def initfname(self):
        return os.path.join(self.path, "init.ini")

    @property
    def outfname(self):
        return os.path.join(self.path, "out.ini")

    @property
    def cfainfname(self):
        return os.path.join(self.path, "cfain.marshal")

    @property
    def cfaoutfname(self):
        return os.path.join(self.path, "cfaout.marshal")

    @property
    def logfname(self):
        return os.path.join(self.path, "analyzer.log")


class LocalAnalyzer(Analyzer, QtCore.QProcess):
    """
    Runs BinCAT locally using QProcess.
    """

    def __init__(self, *args, **kwargs):
        QtCore.QProcess.__init__(self)
        Analyzer.__init__(self, *args, **kwargs)
        # Qprocess signal handlers
        self.error.connect(self.procanalyzer_on_error)
        self.stateChanged.connect(self.procanalyzer_on_state_change)
        self.started.connect(self.procanalyzer_on_start)
        self.finished.connect(self.procanalyzer_on_finish)

    def run(self):
        cmdline = "bincat_native %s %s %s" % (self.initfname, self.outfname,
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
            with open(self.logfname) as f:
                bc_log.debug(f.read())
        bc_log.debug("----------------------------")
        self.finish_cb(self.outfname, self.logfname, self.cfaoutfname)


class WebAnalyzer(Analyzer):
    def __init__(self, *args, **kwargs):
        Analyzer.__init__(self, *args, **kwargs)
        self.server_url = self.options.get("server_url")

    def run(self):
        if 'requests' not in sys.modules:
            bc_log.error("python requests modules could not be imported, "
                         "so remote BinCAT cannot be used.")
            return
        server_url = self.server_url.rstrip('/')
        sha256 = idaapi.retrieve_input_file_sha256().lower()
        binary_file = idaapi.get_input_file_path()
        # patch filepath (XXX dirty, rework AnalyzerConfig?) - set filepath to
        # sha256
        bc_log.debug("PATH %s", binary_file)
        init_ini_str = re.sub(
            '^filepath = .+$',
            'filepath = %s' % sha256,
            open(self.initfname).read(),
            flags=re.MULTILINE)
        if os.path.exists(self.cfainfname):
            with open(self.cfainfname, 'r') as f:
                h = hashlib.new('sha256')
                h.update(f.read())
                cfa_sha256 = h.hexdigest().lower()
            init_ini_str = re.sub(
                '^in_marshalled_cfa_file = .+$',
                'in_marshalled_cfa_file = %s' % cfa_sha256,
                init_ini_str,
                flags=re.MULTILINE)
        bc_log.debug(init_ini_str)
        # check whether file has already been uploaded
        try:
            check_res = requests.head(server_url + "/download/%s" % sha256)
        except requests.exceptions.ConnectionError as e:
            bc_log.error("Error when contacting the BinCAT server: %s", e)
            return
        if check_res.status_code == 404:
            # Confirmation dialog before uploading file?
            msgBox = QtWidgets.QMessageBox()
            msgBox.setText("Do you really want to upload %s to %s?" %
                           (binary_file, server_url))
            msgBox.setStandardButtons(QtWidgets.QMessageBox.Yes |
                                      QtWidgets.QMessageBox.No)
            msgBox.setIcon(QtWidgets.QMessageBox.Question)
            ret = msgBox.exec_()
            if ret == QtWidgets.QMessageBox.No:
                bc_log.info("Upload aborted.")
                return
            # upload
            upload_res = requests.put(
                server_url + "/add",
                files={'file': ('file', open(binary_file, 'rb').read())})
            if upload_res.status_code != 200:
                bc_log.error("Error while uploading binary file "
                             "to BinCAT analysis server.")
                return
        run_res = requests.post(
            server_url + "/analyze",
            files={'init.ini': ('init.ini', init_ini_str)})
        if run_res.status_code != 200:
            bc_log.error("Error while uploading analysis configuration file "
                         "to BinCAT analysis server.")
            return
        files = run_res.json()
        bc_log.info("---- stdout+stderr ----------------")
        bc_log.info(files['stdout'])
        bc_log.debug("---- logfile ---------------")
        bc_log.info(files['analyzer.log'])
        bc_log.debug("----------------------------")
        with open(self.outfname, 'w') as outfp:
            outfp.write(files["out.ini"])
        with open(self.logfname, 'w') as logfp:
            logfp.write(files["analyzer.log"])
        if "cfaout.marshal" in files:
            # might be absent when analysis failed
            cfa_sha256 = files["cfaout.marshal"]
            with open(self.cfaoutfname, 'w') as cfaoutfp:
                cfaout_marshal_str = requests.get(server_url + "/download/" +
                                                  cfa_sha256).content
                cfaoutfp.write(cfaout_marshal_str)
        self.finish_cb(self.outfname, self.logfname, self.cfaoutfname)


class PluginOptions(object):
    def __init__(self):
        # Configuration files path
        idausr = os.getenv('IDAUSR')
        if not idausr:
            if os.name == "nt":
                idausr = os.path.join(
                    os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
            elif os.name == "posix":
                idausr = os.path.join(os.getenv("HOME"), ".idapro")
            else:
                raise RuntimeError
            bc_log.warning("IDAUSR not defined, using %s", idausr)
        self.config_path = os.path.join(idausr, "idabincat")

        # Plugin options
        def_options = {'save_to_idb': "False",
                       "load_from_idb": "True",
                       "server_url": "http://localhost:5000",
                       "web_analyzer": "False",
                       "autostart": "False"}
        self.options = ConfigParser.ConfigParser(defaults=def_options)
        self.options.optionxform = str
        self.configfile = os.path.join(self.config_path, "conf", "options.ini")
        if len(self.options.read(self.configfile)) != 1:
            self.options.add_section("options")

    def get(self, name):
        return self.options.get("options", name)

    def set(self, name, value):
        self.options.set("options", name, value)
        pass

    def save(self):
        with open(self.configfile, "w") as optfile:
            self.options.write(optfile)


class State(object):
    """
    Container for (static) plugin state related data & methods.
    """
    def __init__(self, options):
        self.current_ea = None
        self.options = options
        self.cfa = None
        self.current_state = None
        self.current_node_ids = []
        self.current_config = AnalyzerConfig()
        #: Analyzer instance - protects against merciless garbage collector
        self.analyzer = None
        self.hooks = None
        self.netnode = idabincat.netnode.Netnode("$ com.bincat.bcplugin")
        # for debugging purposes - to interact with this object from the console
        # XXX store in idb after encoding?
        self.last_cfaout_marshal = None
        bc_state = self
        global bc_state

        self.gui = GUI(self)
        if self.options.get("load_from_idb") == "True":
            self.load_from_idb()

    def new_analyzer(self, *args, **kwargs):
        """
        returns current Analyzer class (web or local)
        """
        if (self.options.get("web_analyzer") == "True" and
                self.options.get("server_url") != ""):
            return WebAnalyzer(*args, **kwargs)
        else:
            return LocalAnalyzer(*args, **kwargs)

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
            self.analysis_finish_cb(outfname, logfname, cfaoutfname=None,
                                    ea=ea)

    def clear_background(self):
        """
        reset background color for previous analysis
        """
        if self.cfa:
            color = idaapi.calc_bg_color(idaapi.NIF_BG_COLOR)
            for v in self.cfa.states:
                ea = v.value
                idaapi.set_item_color(ea, color)

    def analysis_finish_cb(self, outfname, logfname, cfaoutfname, ea=None):
        bc_log.debug("Parsing analyzer result file")
        cfa = cfa_module.CFA.parse(outfname, logs=logfname)
        self.clear_background()
        self.cfa = cfa
        if cfa:
            # XXX add user preference for saving to idb? in that case, store
            # reference to marshalled cfa elsewhere
            bc_log.info("Storing analysis results to idb")
            with open(outfname, 'r') as f:
                self.netnode["out.ini"] = f.read()
            with open(logfname, 'r') as f:
                self.netnode["analyzer.log"] = f.read()
            if cfaoutfname is not None:
                with open(cfaoutfname, 'r') as f:
                    self.last_cfaout_marshal = f.read()
        else:
            bc_log.info("Empty or unparseable result file.")
        bc_log.debug("----------------------------")
        # Update current RVA to start address (nodeid = 0)
        # by default, use current ea - e.g, in case there is no results (cfa is
        # None) or no node 0 (happens in backward mode)
        current_ea = self.current_ea
        if ea is not None:
            current_ea = ea
        else:
            try:
                node0 = cfa['0']
                if node0:
                    current_ea = node0.address.value
            except (KeyError, TypeError):
                # no cfa is None, or no node0
                pass
        self.set_current_ea(current_ea, force=True)
        self.netnode["current_ea"] = current_ea
        if not cfa:
            return
        for addr, nodeids in cfa.states.items():
            ea = addr.value
            tainted = False
            for n_id in nodeids:
                # is it tainted?
                # find children state
                state = cfa[n_id]
                if state.tainted:
                    tainted = True
                    break

            if tainted:
                idaapi.set_item_color(ea, 0xDDFFDD)
            else:
                idaapi.set_item_color(ea, 0xCDCFCE)

    def set_current_node(self, node_id):
        if self.cfa:
            if self.cfa[node_id]:
                self.set_current_ea(self.current_state.address.value, force=True, node_id=node_id)

    def set_current_ea(self, ea, force=False, node_id=None):
        """
        :param ea: int or long
        """
        if not (force or ea != self.current_ea):
            return
        self.gui.before_change_ea()
        self.current_ea = ea
        nonempty_state = False
        if self.cfa:
            node_ids = self.cfa.node_id_from_addr(ea)
            if node_ids:
                nonempty_state = True
                if node_id in node_ids:
                    self.current_state = self.cfa[node_id]
                else:
                    self.current_state = self.cfa[node_ids[0]]
                self.current_node_ids = node_ids
        if not nonempty_state:
            self.current_state = None
            self.current_node_ids = []

        self.gui.after_change_ea()

    def start_analysis(self, config_str=None):
        # Creates new temporary dir. File structure:
        # input files: init.ini, cfain.marshal
        # output files: out.ini, cfaout.marshal

        path = tempfile.mkdtemp(suffix='bincat')

        # instance variable: we don't want the garbage collector to delete the
        # *Analyzer instance, killing an unlucky QProcess in the process
        self.analyzer = self.new_analyzer(path, self.options,
                                          self.analysis_finish_cb)

        bc_log.debug("Current analyzer path: %s", path)

        # get RawConfigParser object
        if config_str:
            config = ConfigParser.RawConfigParser()
            config.config.optionxform = str
            config.readfp(StringIO.StringIO(config_str))
        else:
            config = self.current_config.config
        config.set('analyzer', 'out_marshalled_cfa_file',
                   self.analyzer.cfaoutfname)
        config.set('analyzer', 'in_marshalled_cfa_file',
                   self.analyzer.cfainfname)
        config.set('analyzer', 'store_marshalled_cfa', 'true')
        analysis_method = config.get('analyzer', 'analysis').lower()
        if analysis_method in ("forward_cfa", "backward"):
            if self.last_cfaout_marshal is None:
                bc_log.error("No marshalled CFA has been recorded - run a "
                             "forward analysis first.")
                return
            with open(self.analyzer.cfainfname, 'w') as f:
                f.write(self.last_cfaout_marshal)
        with open(self.analyzer.initfname, 'w') as f:
            config.write(f)
        self.analyzer.run()


def PLUGIN_ENTRY():
    return BincatPlugin()
