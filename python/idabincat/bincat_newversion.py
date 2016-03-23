#!/usr/bin/python 


#version IDA 6.8 

 # Imports 
from idaapi import *
from idc import * 
from idautils import *
import threading 
import time
import socket 
import os 
import cPickle 
import subprocess
import sys
import ConfigParser
from collections import OrderedDict



# Loading Qt packages 
try:
	from PyQt5 import QtCore, QtWidgets 
        from PyQt5.QtCore import QProcess , QProcessEnvironment
except:
        idaapi.msg("[+] BinCat : failed to load Qt libs from PyQt5 \n %s"% repr(sys.exc_info()))
        sys.exit(0) 

#------------------------------------
# setting environnement variables 
if sys.platform.startswith('linux'):
        PYTHON_BIN = 'python'
        PYTHON_PATH = os.path.normpath('/usr/bin')





# ----------------------------------------------------------------------------------------------
# Class Analyzer that inherits from Qprocess
# The idea is to implement callbacks on main Qprocess signals 

class Analyzer(QtCore.QProcess):

        def procanalyzer_on_error(self, error):
                errors  = [ "Failed to start" , "Crashed" ,"TimedOut" , "Read Error" , "Write Error" , "Unknown Error"]
                idaapi.msg(" [+] Analyzer error:%s\n"%errors[error])

        def procanalyzer_on_state_change(self, new_state):
                states = ["Not running" , "Starting" , "Running"]
                idaapi.msg(" [+] Analyzer new state : %s\n"%states[new_state])

        def procanalyzer_on_start(self):
                idaapi.msg(" [+] Analyzer Starting call back\n")

        def procanalyzer_on_finish(self):
                idaapi.msg(" [+] Analyzer Terminating call back\n") 

        # for a first test I use this callback to get analyzer output 
        # the goal is exchange information using a qtcpsocket
        def procanalyzer_on_out(self):
                buffer = str(self.readAllStandardOutput()).strip()
                idaapi.msg(" [+] Analyzer standard output \n") 
                idaapi.msg("%s\n"%buffer)


        def __init__(self):
                QtCore.QProcess.__init__(self)
                # attribute different handlers to Qprocess states 
                self.error.connect(self.procanalyzer_on_error)
                self.readyReadStandardOutput.connect(self.procanalyzer_on_out)
                self.stateChanged.connect(self.procanalyzer_on_state_change)
                self.started.connect(self.procanalyzer_on_start)
                self.finished.connect(self.procanalyzer_on_finish)        


# ----------------------------------------------------------------------------------------------
# BinCAT log viewer 

class BinCATLog_t(simplecustviewer_t):
        def Create(self,sn=None):
                # Form title 
                title = "BinCAT Log viewer"
                idaapi.msg(" [+] BinCAT log view created \n")
                # create the custom view 
                if not simplecustviewer_t.Create(self,title):
                        return False

                return True 



        def Log(self,LogLine):
                self.AddLine(LogLine)
                

 
 
# ----------------------------------------------------------------------------------------------
# BinCAT main IDA PluginForm


class BinCATForm_t(PluginForm):


        # function : init_Analyzer() : launch eth analyzer.py process 
        def init_Analyzer(self):
                idaapi.msg(" [+] BinCAT : init_Analyzer() \n")
                #TODO parse analyser config file 
                analyzerpath = self.iptAnalyzerPath.text() 
                address = hex(GetEntryPoint(GetEntryOrdinal(0))).rstrip('L')
                port = 9001
                inifile = "nop.ini"
                outfile = "result.txt"

                cmdline = "%s %s %s --commandfd %s --inifile %s --outfile %s" % (
                                os.path.join(PYTHON_PATH,PYTHON_BIN),analyzerpath,address,port,inifile,outfile)  
                idaapi.msg(" [+] BinCAT : Analyzer cmdline is :\n  %s \n "%cmdline)

                # create Analyzer Object 
                self.analyzer = Analyzer() 
                
                # start the process 
                try :
                        self.analyzer.start(cmdline)
                        idaapi.msg(" ")
                        
                except Exception as e:
                        idaapi.msg(" [+] BinCAT failed to launch the analyzer.py\n")
                        idaapi.msg("    Exception: %s\n%s"%(str(e),traceback.format_exc())) 


        # handler for btnNewAnalyzer
        def handler_btnNewAnalyzer(self):
                options = QtWidgets.QFileDialog.Options()
                fname = QtWidgets.QFileDialog.getOpenFileName(self.parent,'Open file',GetIdaDirectory(),"Python files (*.py)",options=options)
                if fname :
                        self.iptAnalyzerPath.setText(fname[0])


        # Called when the plugin form is created
        def OnCreate(self, form):
                idaapi.msg("[+] BinCAT form created\n")
                # Get parent widget 
                self.parent = self.FormToPyQtWidget(form)

                # create a label 
                label = QtWidgets.QLabel('IDB file :')


                # get idb path 
                idbpath = idaapi.get_root_filename() 
                
                # create an input box 
                self.input = QtWidgets.QLineEdit(self.parent)
                self.input.setText(GetIdbPath())
                self.input.setMaxLength = 256 
                self.input.setFixedWidth(300)


                # create label : analyzer path
                lblAnalyzerPath = QtWidgets.QLabel('Analyzer path :')

                # create input : analyzer path 
                self.iptAnalyzerPath = QtWidgets.QLineEdit(self.parent)

                # analyzer.py file has to be placed by default in IDADIR/BinCAT 
                self.iptAnalyzerPath.setText(idaapi.idadir('python/BinCAT/analyzer.py'))
                self.iptAnalyzerPath.setMaxLength = 256
                self.iptAnalyzerPath.setFixedWidth(300) 

                # button to choose another analyer 
                self.btnNewAnalyzer = QtWidgets.QPushButton('...',self.parent)
                self.btnNewAnalyzer.setToolTip('set a new analyzer.py path') 
                self.btnNewAnalyzer.clicked.connect(self.handler_btnNewAnalyzer)

                # restart button for the analyzer 
                self.btnAnalyzer = QtWidgets.QPushButton('restart',self.parent)
                self.btnAnalyzer.setToolTip('restart analyzer.')
                self.btnAnalyzer.setFixedWidth(150)

                # create a button for analyzer configuration form 
                self.btnAnalyzerConfig = QtWidgets.QPushButton('Analyzer configuration',self.parent)

                # create a Layout 
                layout = QtWidgets.QGridLayout()
                layout.addWidget(label,0,0)
                layout.addWidget(self.input,0,1)
                layout.addWidget(lblAnalyzerPath,1,0)
                layout.addWidget(self.iptAnalyzerPath,1,1)
                layout.addWidget(self.btnAnalyzer,1,3)
                layout.addWidget(self.btnNewAnalyzer,1,2)
                layout.addWidget(self.btnAnalyzerConfig,2,0)

                layout.setColumnStretch(4,1)
                layout.setRowStretch(3,1)
                              
                self.parent.setLayout(layout)

                # Launch the analyzer by calling init_analyzer()
                self.init_Analyzer()

                

        # Called when the plugin form is closed
        def OnClose(self,form):
                idaapi.msg(" [+] BinCAT form closed\n")
                global BinCATForm
                del BinCATForm             

 

        def Show(self):
                return PluginForm.Show(self,"BinCAT",options=PluginForm.FORM_PERSIST)



# ----------------------------------------------------------------------------------------------



def main():
        idaapi.msg("[+] BinCAT plugin loaded\n")
        if not idaapi.get_root_filename():
                idaapi.msg(" [BinCAT] please load a file/idb before \n")
                return

        global BinCATForm
        global BinCATLogViewer

        try:
                BinCATForm
                BinCATLogViewer 
        except:
                BinCATForm = BinCATForm_t() 
                BinCATLogViewer = BinCATLog_t()

        idaapi.msg("[+] BinCAT Starting main form\n")
        BinCATForm.Show()
        
        if BinCATLogViewer.Create(1):
                BinCATLogViewer.Show()

        
         

main()
