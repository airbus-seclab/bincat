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
# Class : create config.ini file that holds the default parameters for the current idb file 

class HelperConfigIniFile:

        def __init__(self):
                self.version = "0.0"
                self.config_ini_path = None

        def getFirstEntryPoint(self): 
                ord0 = GetEntryOrdinal(0)
                funcname = GetFunctionName(ord0)
                return ord0

        def getFileType(self):
                self.ftypes = {idaapi.f_PE:"pe",idaapi.f_ELF:"elf",idaapi.f_MACHO:"macho"}
                ida_db_info_structure = idaapi.get_inf_structure()
                f_type = ida_db_info_structure.filetype
                return self.ftypes[f_type]
                


        def getMemoryModel(self):
                ida_db_info_structure = idaapi.get_inf_structure() 
                compiler_info =  ida_db_info_structure.cc 
                if  (compiler_info.cm & idaapi.C_PC_TINY == 1): return "tiny"
                if  (compiler_info.cm & idaapi.C_PC_SMALL == 1): return "small"
                if  (compiler_info.cm & idaapi.C_PC_COMPACT == 1): return "compact"
                if  (compiler_info.cm & idaapi.C_PC_MEDIUM == 1): return "medium"
                if  (compiler_info.cm & idaapi.C_PC_LARGE == 1): return "large"
                if  (compiler_info.cm & idaapi.C_PC_HUGE == 1): return "huge"
                if  (compiler_info.cm & idaapi.C_PC_FLAT == 3 ): return "flat"

        def getCallConvention(self):
                ida_db_info_structure = idaapi.get_inf_structure() 
                compiler_info =  ida_db_info_structure.cc 
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_INVALID : return "invalid"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_UNKNOWN : return "unknown"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_VOIDARG : return "voidargs"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_CDECL : return "cdecl"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_ELLIPSIS : return "ellipsis"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_STDCALL : return "stdcall"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_PASCAL : return "pascal"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_FASTCALL : return "fastcall"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_THISCALL : return "thiscall"
                if  (compiler_info.cm & CM_CC_MASK ) == CM_CC_MANUAL : return "manual"

        def getBitness(self,ea):
                bitness = idc.GetSegmentAttr( ea , idc.SEGATTR_BITNESS)
                if  bitness == 0 :
                        bitness = 16 
                elif bitness == 1 :
                        bitness = 32 
                elif bitness == 2 :
                        bitness = 64 
                return bitness

        def getStackWidth(self):
                ida_db_info_structure = idaapi.get_inf_structure() 
                if  ida_db_info_structure.is_64bit() :
                        return(8*8)
                else : 
                        if ida_db_info_structure.is_32bit() :
                                return(4*8)
                        else :
                                return(2*8)   


        def getCodeSection(self,ea):
                # in case we have more than one code section we apply the following heuristic 
                # entry point must be in the code section
                BinCATLogViewer.Log(" [+] BinCAT call GetCodeSegment ",SCOLOR_LOCNAME)
  
                ep = self.getFirstEntryPoint()
                for seg in Segments():
                        seg_attributes = idc.GetSegmentAttr(SegStart(seg),idc.SEGATTR_TYPE)
                        if seg_attributes  == idaapi.SEG_CODE and ( SegStart(seg) <= ep  <= SegEnd(seg)  )  : 
                                if ea == 'start' :
                                        log= "[+] BinCAT::getCodeSection start %d "%SegStart(seg)
                                        BinCATLogViewer.Log(log,SCOLOR_LOCNAME)
                                        return( SegStart(seg) )
                                if ea == 'end' :
                                        log = "[+] BinCAT::getCodeSection end %d "%SegStart(seg)
                                        BinCATLogViewer.Log(log,SCOLOR_LOCNAME)
                                        return( SegEnd(seg) )
                                else : 
                                        log = "[+] BinCAT no Code section has been found"
                                        BinCATLogViewer.Log(log,SCOLOR_LOCNAME)
                                        return(-1) 
        def getDataSection(self,ea):
                for seg in Segments():
                        seg_attributes = idc.GetSegmentAttr(SegStart(seg),idc.SEGATTR_TYPE)
                        if seg_attributes  == idaapi.SEG_DATA : 
                                if ea == 'start' :
                                        log= "[+] BinCAT::getDataSection start %d "%SegStart(seg)
                                        BinCATLogViewer.Log(log,SCOLOR_LOCNAME)
                                        return( SegStart(seg) )
                                if ea == 'end' :
                                        log = "[+] BinCAT::getDataSection end %d "%SegStart(seg) 
                                        BinCATLogViewer.Log(log,SCOLOR_LOCNAME)
                                        return( SegEnd(seg) )


        def CreateIniFile(self):
                # this function will grap the default parameters 
                BinCATLogViewer.Log(" [+] BinCAT Creating ini configuration file",SCOLOR_LOCNAME)
                self.configini = ConfigParser.RawConfigParser()
                # [settings] section 
                self.configini.add_section('settings')
                self.configini.set('settings','mem-model',self.getMemoryModel()) 
                self.configini.set('settings','call-conv',self.getCallConvention())
                self.configini.set('settings','mem-sz',32)
                adr  = self.getCodeSection('start')
                self.configini.set('settings','op-sz', self.getBitness( adr ) )
                self.configini.set('settings','stack-width',self.getStackWidth())

                # [loader section] 
                self.configini.add_section('loader')
                self.configini.set('loader','rva-stack','0xFFFFFFFF') 
                self.configini.set('loader','rva-data',hex(self.getDataSection('start')).strip('L'))
                self.configini.set('loader','rva-code-start',hex(self.getCodeSection('start')).strip('L'))
                self.configini.set('loader','rva-code-end',hex(self.getCodeSection('end')).strip('L'))
                self.configini.set('loader','rva-entrypoint', hex(idaapi.get_inf_structure().startIP).strip('L') )

                # [binary section] 
                self.configini.add_section('binary')
                self.configini.set('binary','filename',GetInputFile())
                self.configini.set('binary','filepath',GetInputFilePath()) 
                self.configini.set('binary','format',self.getFileType())
                self.configini.set('binary','phys-code', hex(idaapi.get_fileregion_offset(self.getCodeSection('start'))) )
                
                # [analyzer section] 
                self.configini.add_section('analyzer')
                self.configini.set('analyzer','unroll',5)

                # [state section] 
                self.configini.add_section('state')

                # config ini file should be in the same directory as the IDB file 
                self.config_ini_path = GetIdbDir() + "config.ini"         
                # writing configuration file
                log = "[+] BinCAT Writing config.ini %s \n"%self.config_ini_path 
                BinCATLogViewer.Log(log,SCOLOR_LOCNAME)

                with open(self.config_ini_path,'w') as configfile:
                        self.configini.write(configfile)

# ----------------------------------------------------------------------------------------------
# Class  Tainting Launcher Form 

class TaintLaunchForm_t(QtWidgets.QDialog):
        def btnStartHandler(self):
                self.accept()

        def CancelHandler(self):
                idaapi.msg("Cancel button handler")
                self.reject()

        def foo(self, *args, **kargs):
                idaapi.msg("Foo %r %r" % (args,kargs))

        def __init__(self,parent):
                super(TaintLaunchForm_t,self).__init__(parent)
                
                layout = QtWidgets.QGridLayout()
                lblCstEditor = QtWidgets.QLabel(" Start taint analysis : ") 

                # Start address 
                lblStartAdr = QtWidgets.QLabel(" Start address : ") 
                ipStartAdr = QtWidgets.QLineEdit(self)
                ipStartAdr.setText(hex(here()).rstrip('L'))
                               
                # End address 
                lblEndAdr = QtWidgets.QLabel(" End address   : ") 
                ipEndAdr = QtWidgets.QLineEdit(self)

                # Tainting element register or memory
                lblTntElem = QtWidgets.QLabel(" Tainted element   : ") 

                # radio button register
                rbRegisters = QtWidgets.QRadioButton("Register")
                ipRegs = QtWidgets.QLineEdit(self)
                
                # radio button memory 
                rbMemory = QtWidgets.QRadioButton("Memory")
                ipMemory = QtWidgets.QLineEdit(self)
                
                # Start , cancel and analyzer config buttons
                self.btnStart = QtWidgets.QPushButton('Start',self)
                self.btnStart.setToolTip('Save Constraints.')
                self.btnStart.setFixedWidth(130)
                idaapi.msg(" call connect btn \n ")
                self.btnStart.clicked.connect(self.foo)


                self.btnCancel = QtWidgets.QPushButton('Cancel',self)
                self.btnCancel.setToolTip('Cancel.')
                self.btnCancel.setFixedWidth(130)
                self.btnCancel.clicked.connect(self.close)


                self.btnAc = QtWidgets.QPushButton('Analyzer configuration',self)
                self.btnAc.setToolTip('Configure the analyzer.')
                self.btnAc.setFixedWidth(150)
                #self.btnAc.clicked.connect()

                layout.addWidget(lblCstEditor,0,0)

                layout.addWidget(lblStartAdr,1,0)
                layout.addWidget(ipStartAdr,1,1)
                
                layout.addWidget(lblEndAdr,2,0)
                layout.addWidget(ipEndAdr,2,1)

                layout.addWidget(rbRegisters,3,0)
                layout.addWidget(ipRegs,3,1)

                layout.addWidget(rbMemory,4,0)
                layout.addWidget(ipMemory,4,1)

                layout.addWidget(self.btnStart,5,0)
                layout.addWidget(self.btnCancel,5,1)
                layout.addWidget(self.btnAc,5,2)


                layout.setColumnStretch(3,1)
                layout.setRowStretch(6,1)

                self.setLayout(layout)
 
        
        def show(self):
                self.setFixedSize(460,200)
                self.setWindowTitle(" Analysis launcher : ")
                super(TaintLaunchForm_t,self).show()


# ----------------------------------------------------------------------------------------------
# Class Constraintes editor 
class ConstrainteEditorForm_t(QtWidgets.QDialog):
        def btnOKHandler(self):
                self.accept()

        def btnCancelHandler(self):
                self.reject()


        def __init__(self,parent):
                super(ConstrainteEditorForm_t,self).__init__(parent)
                
                layout = QtWidgets.QGridLayout()
                lblCstEditor = QtWidgets.QLabel(" Constraintes Editor : ") 
                layout.addWidget(lblCstEditor,0,0)

                self.notes = QtWidgets.QPlainTextEdit() 
                self.notes.setFixedHeight(300)
                self.notes.setFixedWidth(300)
                self.notes.appendPlainText("reg[eax] = 0x00")
                self.notes.appendPlainText("mem[0x4000] = 0x00")

                # OK and cancel button
                self.btnOK = QtWidgets.QPushButton('OK',self)
                self.btnOK.setToolTip('Save Constraints.')
                self.btnOK.setFixedWidth(150)
                self.btnOK.clicked.connect(self.btnOKHandler)


                self.btnCancel = QtWidgets.QPushButton('Cancel',self)
                self.btnCancel.setToolTip('Cancel.')
                self.btnCancel.setFixedWidth(150)
                self.btnCancel.clicked.connect(self.btnCancelHandler)


                layout.addWidget(self.notes,1,0)
                layout.addWidget(self.btnOK,2,0)
                layout.addWidget(self.btnCancel,2,1)


                layout.setColumnStretch(2,1)
                layout.setRowStretch(3,1)

                self.setLayout(layout)
 
        
        def show(self):
                self.setFixedSize(400,400)
                self.setWindowTitle("Constraints Editor")
                super(ConstrainteEditorForm_t,self).show()

# ----------------------------------------------------------------------------------------------
# Class AnalyzerConfForm : this forms is populated by the content of the nop.ini file 
#       This form helps the en user to configure the analyzer

class AnalyzerConfForm_t(QtWidgets.QDialog):

        def btnCstrHandler(self):
                CstEdit = ConstrainteEditorForm_t(self)
                CstEdit.show()

        def btnCancelHandler(self):
                self.reject()
 
        def btnOKHandler(self):
                self.accept() 

        def __init__(self,parent):
                super(AnalyzerConfForm_t,self).__init__(parent)

                # Get config ini file 
                #hlpConfig = HelperConfigIniFile()
                self.currentConfig = ConfigParser.ConfigParser()
                self.currentConfig.read(hlpConfig.config_ini_path)


                # based on the analyzer ini file (see test/nop.ini)
                # Settings label 
                lblSettings = QtWidgets.QLabel("[Settings] : ")
                layout = QtWidgets.QGridLayout()
                layout.addWidget(lblSettings,0,0)

                

                # mem-model 
                lblmemmodel = QtWidgets.QLabel(" mem-model : ")
                layout.addWidget(lblmemmodel,1,0)

                self.iptmm = QtWidgets.QLineEdit(self)

                self.iptmm.setText(self.currentConfig.get('settings','mem-model'))
                self.iptmm.setMaxLength = 256
                self.iptmm.setFixedWidth(200) 
                
                layout.addWidget(self.iptmm,1,1)


                # call-conv 
                lblcallconv = QtWidgets.QLabel(" call-conv : ")
                layout.addWidget(lblcallconv,2,0)
               
                self.iptcc = QtWidgets.QLineEdit(self)

                self.iptcc.setText(self.currentConfig.get('settings','call-conv'))
                self.iptcc.setMaxLength = 256
                self.iptcc.setFixedWidth(200) 
                
                layout.addWidget(self.iptcc,2,1)
 
                # mem-size 
                lblmemsize = QtWidgets.QLabel(" mem-size : ") 
                layout.addWidget(lblmemsize,3,0)

                self.iptms = QtWidgets.QLineEdit(self)

                self.iptms.setText(self.currentConfig.get('settings','mem-sz'))
                self.iptms.setMaxLength = 256
                self.iptms.setFixedWidth(200) 
                
                layout.addWidget(self.iptms,3,1)

                # op-sz 
                lblopsz = QtWidgets.QLabel(" op-sz : ") 
                layout.addWidget(lblopsz,4,0)
                self.iptos = QtWidgets.QLineEdit(self)

                self.iptos.setText(self.currentConfig.get('settings','op-sz'))
                self.iptos.setMaxLength = 256
                self.iptos.setFixedWidth(200) 
                
                layout.addWidget(self.iptos,4,1)

                # stack-width
                lblstackwidth = QtWidgets.QLabel(" stack-width : ") 
                layout.addWidget(lblstackwidth,5,0)
                self.iptsw = QtWidgets.QLineEdit(self)

                self.iptsw.setText(self.currentConfig.get('settings','stack-width'))
                self.iptsw.setMaxLength = 256
                self.iptsw.setFixedWidth(200) 
                
                layout.addWidget(self.iptsw,5,1)

                # loader label 
                lblLoader = QtWidgets.QLabel("[Loader] : ")
                layout.addWidget(lblLoader,6,0)

                # rva-stack 
                lblrvastack = QtWidgets.QLabel(" rva-stack : ") 
                layout.addWidget(lblrvastack,7,0)
                self.iptrs = QtWidgets.QLineEdit(self)

                self.iptrs.setText(self.currentConfig.get('loader','rva-stack'))
                self.iptrs.setMaxLength = 256
                self.iptrs.setFixedWidth(200) 
                
                layout.addWidget(self.iptrs,7,1)

                # rva-data 
                lblrvadata = QtWidgets.QLabel(" rva-data : ") 
                layout.addWidget(lblrvadata,8,0)
                self.iptrd = QtWidgets.QLineEdit(self)

                self.iptrd.setText(self.currentConfig.get('loader','rva-data'))
                self.iptrd.setMaxLength = 256
                self.iptrd.setFixedWidth(200) 
                
                layout.addWidget(self.iptrd,8,1)

                # rva-code-start 
                lblrvacs = QtWidgets.QLabel(" rva-code-start : ") 
                layout.addWidget(lblrvacs,9,0)
                self.iptrvacs = QtWidgets.QLineEdit(self)

                self.iptrvacs.setText(self.currentConfig.get('loader','rva-code-start'))
                self.iptrvacs.setMaxLength = 256
                self.iptrvacs.setFixedWidth(200) 
                
                layout.addWidget(self.iptrvacs,9,1)
                
                # rva-code-end 
                lblrvace = QtWidgets.QLabel(" rva-code-end : ") 
                layout.addWidget(lblrvace,10,0)
                self.iptrvace = QtWidgets.QLineEdit(self)

                self.iptrvace.setText(self.currentConfig.get('loader','rva-code-end'))
                self.iptrvace.setMaxLength = 256
                self.iptrvace.setFixedWidth(200) 
                
                layout.addWidget(self.iptrvace,10,1)

                # rva-entrypoint 
                lblrvaep = QtWidgets.QLabel(" rva-entrypoint : ") 
                layout.addWidget(lblrvaep,11,0)
                self.iptrvaep = QtWidgets.QLineEdit(self)

                self.iptrvaep.setText(self.currentConfig.get('loader','rva-entrypoint'))
                self.iptrvaep.setMaxLength = 256
                self.iptrvaep.setFixedWidth(200) 
                
                layout.addWidget(self.iptrvaep,11,1)

                # Binary label 
                lblBinary = QtWidgets.QLabel("[Binary] : ")
                layout.addWidget(lblBinary,12,0)

                # filepath 
                lblfilepath = QtWidgets.QLabel(" filepath : ") 
                layout.addWidget(lblfilepath,13,0)
                self.iptfp = QtWidgets.QLineEdit(self)

                self.iptfp.setText(self.currentConfig.get('binary','filename'))
                self.iptfp.setMaxLength = 256
                self.iptfp.setFixedWidth(200) 
                
                layout.addWidget(self.iptfp,13,1)

                # format 
                lblformat = QtWidgets.QLabel(" format : ") 
                layout.addWidget(lblformat,14,0)
                self.iptfmt = QtWidgets.QLineEdit(self)

                self.iptfmt.setText(self.currentConfig.get('binary','format'))
                self.iptfmt.setMaxLength = 256
                self.iptfmt.setFixedWidth(200) 
                
                layout.addWidget(self.iptfmt,14,1)

                # code section phys start adr  
                lblpc = QtWidgets.QLabel(" phys-code : ") 
                layout.addWidget(lblpc,15,0)
                self.iptpc = QtWidgets.QLineEdit(self)

                self.iptpc.setText(self.currentConfig.get('binary','phys-code'))
                self.iptpc.setMaxLength = 256
                self.iptpc.setFixedWidth(200) 
                
                layout.addWidget(self.iptpc,15,1)

                # analyzer label 
                lblBinary = QtWidgets.QLabel("[Analyzer] : ")
                layout.addWidget(lblBinary,16,0)

                # unroll 
                lblur = QtWidgets.QLabel(" unroll : ") 
                layout.addWidget(lblur,17,0)
                self.iptur = QtWidgets.QLineEdit(self)

                self.iptur.setText(self.currentConfig.get('analyzer','unroll'))
                self.iptur.setMaxLength = 256
                self.iptur.setFixedWidth(200) 
                
                layout.addWidget(self.iptur,17,1)

                # State label 
                lblstate = QtWidgets.QLabel("[State] : ")
                layout.addWidget(lblstate,18,0)

                self.btnConstrainte = QtWidgets.QPushButton('Define tainting constraints',self)
                self.btnConstrainte.clicked.connect(self.btnCstrHandler)
                layout.addWidget(self.btnConstrainte,18,1)


                # OK and cancel button 
                self.btnOK = QtWidgets.QPushButton('OK',self)
                self.btnOK.clicked.connect(self.btnOKHandler)
                layout.addWidget(self.btnOK,19,0)

                self.btnCancel = QtWidgets.QPushButton('Cancel',self)
                self.btnCancel.clicked.connect(self.btnCancelHandler)
                layout.addWidget(self.btnCancel,19,1)
                

                # Setting the layout 
                layout.setColumnStretch(4,1)
                layout.setRowStretch(20,1)
                self.setLayout(layout)
                


        def show(self):
                # width x height
                self.setFixedSize(350,575)
                self.setWindowTitle("Analyzer Configuration")
                super(AnalyzerConfForm_t,self).show()



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
                lines = buffer.splitlines()
                for line in lines:
                        if(line):
                                BinCATLogViewer.Log(line,SCOLOR_DNAME)
                


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



        def Log(self,LogLine,color):
                coloredline = idaapi.COLSTR(LogLine,color)
                self.AddLine(coloredline)
                

# ----------------------------------------------------------------------------------------------
# BinCAT Tainted values form 
# This form containes the values of tainted registers and memory 

class BinCATTaintedForm_t(PluginForm):

        def OnCreate(self,form):
                BinCATLogViewer.Log("[+] BinCAT Creating Tainted form ",SCOLOR_LOCNAME)
                
                # Get parent widget 
                self.parent = self.FormToPyQtWidget(form)
                self.registers_x86 = ['EAX','EBX','ECX','EDX','ESI','EDI','ESP','EBP']
                 
                # Main table 
                self.table = QtWidgets.QTableWidget() 
                self.table.setColumnCount(3)
                self.table.setRowCount(len(self.registers_x86))

                self.table.setHorizontalHeaderItem(0,QtWidgets.QTableWidgetItem("Registers"))
                self.table.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem("Tainted"))
                self.table.setHorizontalHeaderItem(2,QtWidgets.QTableWidgetItem("Values"))

                self.table.setColumnWidth(0, 80)
                self.table.setColumnWidth(1, 80)
                self.table.setColumnWidth(2, 100)

                # populate table 
                index = 0 
                for reg in self.registers_x86:
                        item = QtWidgets.QTableWidgetItem(reg)
                        self.table.setItem(index, 0, item)
                        index+=1

                self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
                layout = QtWidgets.QGridLayout()
                self.table.verticalHeader().setDefaultSectionSize(15)

                layout.addWidget(self.table,0,0)
                #label = QtWidgets.QLabel('Tainting :')
                #layout.addWidget(label,0,0)

                layout.setColumnStretch(0,1)
                layout.setRowStretch(0,1)

                self.parent.setLayout(layout)

        # Called when the plugin form is closed
        def OnClose(self,form):
                BinCATLogViewer.Log(" [+] BinCAT Closing Tainted form ",SCOLOR_LOCNAME)
                


        def Show(self):
                return PluginForm.Show(self,"BinCAT Tainting",options=PluginForm.FORM_PERSIST | PluginForm.FORM_TAB)
 
 
# ----------------------------------------------------------------------------------------------
# BinCAT main IDA PluginForm


class BinCATForm_t(PluginForm):

        # init local tcp port 
        def init_Local_Socket(self):
                BinCATLogViewer.Log("[+] BinCAT : creating local socket ",SCOLOR_LOCNAME)



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

        def handler_btnAnalyzerConfig(self):
                # Call AnalyzerConfForm_t 
                bAc = AnalyzerConfForm_t(self.parent)
                bAc.show()
                idaapi.msg("handler_btnAnalyzerConfig()\n")

        def handler_restartAnalyzer(self):
                # check if the field is not empty 
                if not self.iptAnalyzerPath.text():
                        BinCATLogViewer.Log(" [+] BinCAT new analyzer path is empty.",SCOLOR_LOCNAME)
                        idaapi.warning(" BinCAT: The analyer could not be started : new path is empty.")
                else : 
                        try:
                                with open(self.iptAnalyzerPath.text()) as file:
                                        #TODO check if the analyer.py is the correct stub 
                                        BinCATLogViewer.Log(" [+] BinCAT : restarting analyzer.",SCOLOR_LOCNAME)
                                        self.init_Analyzer()
                                        
                                                           
                        except:
                                BinCATLogViewer.Log(" [+] BinCAT new analyzer file could not be opened.",SCOLOR_LOCNAME)
                                idaapi.warning(" BinCAT: The analyer could not be started : file not found.")
                                                                
                        
                idaapi.msg("[+] BinCAT : new analyzer path %s.\n "%self.iptAnalyzerPath.text()) 


        # Called when the plugin form is created
        def OnCreate(self, form):
                idaapi.msg("[+] BinCAT form created\n")
                BinCATLogViewer.Log("[+] BinCAT form created",SCOLOR_LOCNAME)
                
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
                self.btnAnalyzer.clicked.connect(self.handler_restartAnalyzer)

                # create a button for analyzer configuration form 
                self.btnAnalyzerConfig = QtWidgets.QPushButton('Analyzer configuration',self.parent)
                self.btnAnalyzerConfig.clicked.connect(self.handler_btnAnalyzerConfig)

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

                idaapi.msg(" type(self) %s\n"%type(self))
                idaapi.msg(" type(self.parent) %s \n"%type(self.parent))
                # Launch the analyzer by calling init_analyzer()
                self.init_Analyzer()

                

        # Called when the plugin form is closed
        def OnClose(self,form):
                idaapi.msg(" [+] BinCAT form closed\n")
                BinCATLogViewer.Log(" [+] BinCAT form closed",SCOLOR_LOCNAME)
                
                global BinCATForm
                del BinCATForm   

                #f = idaapi.find_tform("BinCAT Log viewer")
                #if f :
                #        idaapi.close_tform(f,0) 

        def Show(self):
                return PluginForm.Show(self,"BinCAT",options=PluginForm.FORM_PERSIST | PluginForm.FORM_TAB)
# ----------------------------------------------------------------------------------------------
# Action handler for BinCAT/ Taint current basic bloc 
class HtooltipT(idaapi.action_handler_t):
        def __init__(self):
                idaapi.action_handler_t.__init__(self)

        def activate(self,ctx):
                idaapi.msg(" activating HtooltipT ")
                idaapi.warning(" BinCAT: Tainting current Basic Bloc")
                return 1

        def update(self,ctx):
                return idaapi.AST_ENABLE_ALWAYS
# ----------------------------------------------------------------------------------------------
# Action handler for BinCAT/ Taint current function 
class HtooltipF(idaapi.action_handler_t):
        def __init__(self):
                idaapi.action_handler_t.__init__(self)

        def activate(self,ctx):
                idaapi.msg(" activating HtooltipF ")
                idaapi.warning(" BinCAT: Tainting current Function")
                return 1

        def update(self,ctx):
                return idaapi.AST_ENABLE_ALWAYS
# ----------------------------------------------------------------------------------------------
# Action handler for BinCAT/ Taint from here 
class HtooltipH(idaapi.action_handler_t):
        def __init__(self):
                idaapi.action_handler_t.__init__(self)

        def activate(self,ctx):
                idaapi.msg(" activating HtooltipH ")
                #idaapi.warning(" BinCAT: Tainting from current position : %08x "%here())
                idaview = PluginForm.FormToPyQtWidget(get_tform_idaview(ctx.form))
                AnalyzerLauncher = TaintLaunchForm_t(idaview)
                AnalyzerLauncher.show()
                
                return 1

        def update(self,ctx):
                return idaapi.AST_ENABLE_ALWAYS

# ----------------------------------------------------------------------------------------------
# Class Hooks for BinCAT menu 

class  Hooks(idaapi.UI_Hooks):

        def updating_actions(self,ctx):
                if ctx.form_type ==  idaapi.BWN_DISASM:
                        idaview =  get_tform_idaview(ctx.form)
                        place, x , y = get_custom_viewer_place(idaview,False)
                        #line =  get_custom_viewer_curline(idaview,False)
                        if isCode(idaapi.getFlags(place.toea())):
                                #SetColor(place.toea(),CIC_ITEM,0x0CE505)
                                idaapi.msg("%s at EA: %08x \n" % (ctx.form_title,place.toea()))                        


        def populating_tform_popup(self,form,popup):
                idaapi.msg("Hooks called \n")
                #idaapi.attach_action_to_popup(form,popup,"my:tooltip0","BinCAT/Tainting/",idaapi.SETMENU_APP)
                #idaapi.attach_action_to_popup(form,popup,"my:tooltip1","BinCAT/Tainting/",idaapi.SETMENU_APP)
                idaapi.attach_action_to_popup(form,popup,"my:tooltip2","BinCAT/Tainting/",idaapi.SETMENU_APP)

# ----------------------------------------------------------------------------------------------



def main():
        idaapi.msg("[+] BinCAT plugin loaded\n")
        if not idaapi.get_root_filename():
                idaapi.msg(" [BinCAT] please load a file/idb before \n")
                return

        global BinCATForm
        global BinCATLogViewer
        global hlpConfig
        global hooks
        global BinCATTaintedForm
        try:
                BinCATForm
                BinCATLogViewer
                BinCATTaintedForm 
        except:
                BinCATForm = BinCATForm_t() 
                BinCATLogViewer = BinCATLog_t()
                BinCATTaintedForm = BinCATTaintedForm_t() 

        idaapi.msg("[+] BinCAT Starting main form\n")
        if BinCATLogViewer.Create(1):
                BinCATLogViewer.Show()
                idaapi.set_dock_pos("BinCAT Log viewer","Output window",idaapi.DP_LEFT) 
                BinCATLogViewer.Log("[+] BinCAT Starting main form",SCOLOR_LOCNAME)
        
        BinCATForm.Show()
        BinCATTaintedForm.Show() 
        

        idaapi.set_dock_pos("BinCAT","IDA View-A",idaapi.DP_TAB) 
                
        # We create a disassembly view dedicated to BinCAT
        idaapi.open_disasm_window("Tainting View")
        idaapi.set_dock_pos("IDA View-Tainting View","IDA View-A",idaapi.DP_TAB) 
        idaapi.set_dock_pos("BinCAT Tainting","Functions window",idaapi.DP_TAB) 

        # set the focus to BinCAT view
        ida_bincat_view = idaapi.find_tform("BinCAT")
        idaapi.switchto_tform(ida_bincat_view,1)   

        # creating BinCAT menu
        BinCATLogViewer.Log("[+] BinCAT Creating Menus ",SCOLOR_LOCNAME)
        #tooltip_act0 = idaapi.action_desc_t('my:tooltip0','BinCAT : Taint this basic bloc', HtooltipT(),'','BinCAT action',-1)
        #tooltip_act1 = idaapi.action_desc_t('my:tooltip1','BinCAT : Taint this function', HtooltipF(),'','BinCAT action',-1)
        tooltip_act2 = idaapi.action_desc_t('my:tooltip2','BinCAT : Analyze from here', HtooltipH(),'','BinCAT action',-1)

        # Registering BinCAT actions
        #idaapi.register_action(tooltip_act0)
        #idaapi.register_action(tooltip_act1)
        idaapi.register_action(tooltip_act2)

                
        idaapi.attach_action_to_menu("View/","my:tooltip0",idaapi.SETMENU_APP)

        BinCATLogViewer.Log("[+] BinCAT Setting Menu Hooks ",SCOLOR_LOCNAME)


        try :
                hooks.unhook()
                hooks = None 
                idaapi.msg("unhooked")
                
        except:
                hooks = Hooks()
                hooks.hook()        


        # Create a default config.ini file     
        hlpConfig = HelperConfigIniFile()
        hlpConfig.CreateIniFile()
# ----------------------------------------------------------------------------------------------

main()
