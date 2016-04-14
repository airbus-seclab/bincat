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


# Loading analyzer_state 

try:
        import analyzer_state
except:
        idaapi.msg("[+] BinCat : failed to load analyzer_state \n %s"% repr(sys.exc_info()))
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
                #self.configini = ConfigParser.RawConfigParser()
                self.configini = ConfigParser.ConfigParser()
		self.configini.optionxform = str


                # [settings] section 
                self.configini.add_section('settings')
                self.configini.set('settings','mem-model',self.getMemoryModel()) 
                # TODO get cpu mode from idaapi ?  
                self.configini.set('settings','mode','protected') 
                self.configini.set('settings','call-conv',self.getCallConvention())
                self.configini.set('settings','mem-sz',32)
                adr  = self.getCodeSection('start')
                self.configini.set('settings','op-sz', self.getBitness( adr ) )
                self.configini.set('settings','stack-width',self.getStackWidth())

                # [loader section] 
                self.configini.add_section('loader')
                self.configini.set('loader','rva-code',hex(self.getCodeSection('start')).strip('L'))
                self.configini.set('loader','entrypoint', hex(idaapi.get_inf_structure().startIP).strip('L') )
                self.configini.set('loader','phys-code-addr', hex(idaapi.get_fileregion_offset(self.getCodeSection('start'))) )
		# By default code-length is 0 
                self.configini.set('loader','code-length', '0')

                self.configini.set('loader','cs', '0x73')
                self.configini.set('loader','ds', '0x7b')
                self.configini.set('loader','ss', '0x7b')
                self.configini.set('loader','es', '0x7b')
                self.configini.set('loader','ds', '0x7b')
                self.configini.set('loader','fs', '0x7b')
                self.configini.set('loader','gs', '0x7b')
                
                # [binary section] 
                self.configini.add_section('binary')
                #self.configini.set('binary','filename',GetInputFile())
                self.configini.set('binary','filepath',GetInputFilePath()) 
                self.configini.set('binary','format',self.getFileType())


                # [import] section
                self.configini.add_section('imports')
                self.configini.set('imports','0x04','libc,open')

                # [GDT] section
                self.configini.add_section('GDT')
                self.configini.set('GDT','GDT[0]', '0x0000000000000000')
                self.configini.set('GDT','GDT[1]','0x0000000000000000')
                self.configini.set('GDT','GDT[2]','0x0000000000000000')
                self.configini.set('GDT','GDT[3]','0x0000000000000000')
                self.configini.set('GDT','GDT[4]','0x0000000000000000')
                self.configini.set('GDT','GDT[5]','0x0000000000000000')
                self.configini.set('GDT','GDT[6]','0x0000000000000000')
                self.configini.set('GDT','GDT[7]','0x0000000000000000')
                self.configini.set('GDT','GDT[8]','0x0000000000000000')
                self.configini.set('GDT','GDT[9]','0x0000000000000000')
                self.configini.set('GDT','GDT[10]','0x0000000000000000')
                self.configini.set('GDT','GDT[11]','0x0000000000000000')
                self.configini.set('GDT','GDT[12]','0x0000ffff00cf9b00')
                self.configini.set('GDT','GDT[13]','0x0000ffff00cf9300')
                self.configini.set('GDT','GDT[14]','0x0000ffff00cffb00')
                self.configini.set('GDT','GDT[15]','0x0000ffff00cff300')
                self.configini.set('GDT','GDT[16]','0xfac0206bf7008bb7')
                self.configini.set('GDT','GDT[17]','0xd0000fffd4008254')
                self.configini.set('GDT','GDT[18]','0x0000ffff00409a00')
                self.configini.set('GDT','GDT[19]','0x0000ffff00009a00')
                self.configini.set('GDT','GDT[20]','0x0000ffff00009200')
                self.configini.set('GDT','GDT[21]','0x0000000000009200')
                self.configini.set('GDT','GDT[22]','0x0000000000009200')
                self.configini.set('GDT','GDT[23]','0x0000ffff00409a00')
                self.configini.set('GDT','GDT[24]','0x0000ffff00009a00')
                self.configini.set('GDT','GDT[25]','0x0000ffff00409200')
                self.configini.set('GDT','GDT[26]','0x0000ffff00cf9200')
                self.configini.set('GDT','GDT[27]','0x0000ffff368f9325')
                self.configini.set('GDT','GDT[28]','0x1c800018f74091b8')
                self.configini.set('GDT','GDT[29]','0x0000000000000000')
                self.configini.set('GDT','GDT[30]','0x0000000000000000')
                self.configini.set('GDT','GDT[31]','0x8800206bc1008980')
 
                # [analyzer section] 
                self.configini.add_section('analyzer')
                self.configini.set('analyzer','unroll',5)
                self.configini.set('analyzer','dotfile','cfa.dot')

                # [state section] 
                self.configini.add_section('state')
                self.configini.set('state','reg[eax]','0x01 ! 0xff ? 0xf0')
                self.configini.set('state','reg[ebx]','0x02')
                self.configini.set('state','reg[ecx]','0x03')
                self.configini.set('state','reg[edi]','0x04')
                self.configini.set('state','reg[esi]','0x05')
                self.configini.set('state','reg[esp]','0x06')
                self.configini.set('state','reg[ebp]','0x07')

                self.configini.set('state','mem[0x01]','0x1234567812345678 ! 0xff')

                # [libc section] 
                self.configini.add_section('libc')
                self.configini.set('libc','call-conv','fastcall')
                self.configini.set('libc','*','open(@, _)')
                self.configini.set('libc','*','read<stdcall>(@, *, @)')


                # config ini file should be in the same directory as the IDB file 
                self.config_ini_path = GetIdbDir() + "config.ini"         
                # writing configuration file
                log = "[+] BinCAT Writing config.ini %s \n"%self.config_ini_path 
                BinCATLogViewer.Log(log,SCOLOR_LOCNAME)

                with open(self.config_ini_path,'w') as configfile:
                        self.configini.write(configfile)
# ----------------------------------------------------------------------------------------------
# Class  Toto test form 
# To delete 

class Toto_t(QtWidgets.QDialog):

        def foo(self, *args, **kargs):
                idaapi.msg("Foo %r %r" % (args,kargs))


        def __init__(self,parent):
                super(Toto_t,self).__init__(parent)
                 
                layout = QtWidgets.QGridLayout()

                self.btnCcl = QtWidgets.QPushButton('Cancel',self)
                self.btnCcl.setToolTip('Cancel.')
                self.btnCcl.setFixedWidth(130)
                self.btnCcl.clicked.connect(self.foo)

                layout.addWidget(self.btnCcl,1,0)

                layout.setColumnStretch(2,1)
                layout.setRowStretch(2,1)

                self.setLayout(layout)
 
        
        def show(self):
                self.setFixedSize(460,200)
                self.setWindowTitle(" Toto dialog form : ")
                super(Toto_t,self).show()

# ----------------------------------------------------------------------------------------------
# Class  Tainting Launcher Form 

class TaintLaunchForm_t(QtWidgets.QDialog):

        def rbRegistersHandler(self):
               self.cbRegisters.setEnabled(True)
               self.ipMemory.setDisabled(True) 

        def rbMemoryHandler(self):
               self.cbRegisters.setDisabled(True)
               self.ipMemory.setEnabled(True) 

        def cbRegistersHandler(self,text):
                idaapi.msg(" selected register is %s \n "%text)


        def btnLaunchAnalyzer(self):
                BinCATLogViewer.Log("[+] BinCAT : Launching the analyzer",SCOLOR_LOCNAME)
                # Test if End adress is not empty 
                if  not self.ipEndAdr.text():
                        idaapi.warning(" End address is empty")
                else:   
                        # load the config file  for read and update 
                        self.currentConfig = ConfigParser.ConfigParser()
			self.currentConfig.optionxform =  str

                        self.currentConfig.read(hlpConfig.config_ini_path)
                        # get the code length 
                        # We apply  : code-length = Rva-code - startAddress + 2 
                        cl = int(self.ipEndAdr.text(),16)  - int(self.ipStartAdr.text(),16) 

			# code-length =  rva-code - entrypoint + cl
                        rvacode = int(self.currentConfig.get('loader','rva-code'),16)
                        self.currentConfig.set('loader','entrypoint',self.ipStartAdr.text())
			ep =  int(self.ipStartAdr.text(),16)  
			cl  = (ep - rvacode) + cl   

                        # update config.ini file 
                        self.currentConfig.set('loader','code-length',cl)

                        with open(hlpConfig.config_ini_path,'w') as configFile:
                                self.currentConfig.write(configFile)

                        # start the analyzer
                	analyzerpath = BinCATForm.iptAnalyzerPath.text() 
                	inifile = hlpConfig.config_ini_path 
                	outfile = GetIdbDir()+"result.txt"
			logfile = GetIdbDir()+"logfile.txt"

                	cmdline = "%s %s --inifile %s --outfile %s --logfile %s" % (
                                os.path.join(PYTHON_PATH,PYTHON_BIN),analyzerpath,inifile,outfile,logfile)  
 
                	# create Analyzer Object 
                	self.analyzer = Analyzer() 
                
                	# start the process 
                	try :
                		idaapi.msg(" [+] BinCAT : Analyzer cmdline is :\n  %s \n "%cmdline)
                        	self.analyzer.start(cmdline)
                        	idaapi.msg(" ")
                        
                	except Exception as e:
                        	idaapi.msg(" [+] BinCAT failed to launch the analyzer.py\n")
                        	idaapi.msg("    Exception: %s\n%s"%(str(e),traceback.format_exc())) 

			# close the form  : Bug : block the process
                        if self.analyzer.waitForStarted('100') :
			        self.close()


        def btnAnalyzerConfig(self):
                BinCATLogViewer.Log("[+] BinCAT : Loading the analyzer configuration",SCOLOR_LOCNAME)
                bAc = AnalyzerConfForm_t(self)
                bAc.exec_()
                 

        def __init__(self,parent):
                super(TaintLaunchForm_t,self).__init__(parent)
                
                layout = QtWidgets.QGridLayout()
                lblCstEditor = QtWidgets.QLabel(" Start taint analysis : ") 

                # Start address 
                lblStartAdr = QtWidgets.QLabel(" Start address : ") 
                self.ipStartAdr = QtWidgets.QLineEdit(self)
                self.ipStartAdr.setText(hex(here()).rstrip('L'))
                               
                # End address 
                lblEndAdr = QtWidgets.QLabel(" End address   : ") 
                self.ipEndAdr = QtWidgets.QLineEdit(self)

                # Tainting element register or memory
                lblTntElem = QtWidgets.QLabel(" Tainted element   : ") 

                # radio button register
                rbRegisters = QtWidgets.QRadioButton("Register")
                rbRegisters.toggled.connect(self.rbRegistersHandler)
                self.cbRegisters = QtWidgets.QComboBox(self)

                for reg in registers_x86:
                        self.cbRegisters.addItem(reg)

                self.cbRegisters.setDisabled(True)
                self.cbRegisters.activated[str].connect(self.cbRegistersHandler)
 
                #self.ipRegs = QtWidgets.QLineEdit(self)
                #self.ipRegs.setDisabled(True)
                
                # radio button memory 
                rbMemory = QtWidgets.QRadioButton("Memory")
                rbMemory.toggled.connect(self.rbMemoryHandler)
                self.ipMemory = QtWidgets.QLineEdit(self)
                self.ipMemory.setDisabled(True)
                
                # Start , cancel and analyzer config buttons
                self.btnStart = QtWidgets.QPushButton('Start',self)
                self.btnStart.setToolTip('Save Constraints.')
                self.btnStart.setFixedWidth(130)
                self.btnStart.clicked.connect(self.btnLaunchAnalyzer)

                self.btnCancel = QtWidgets.QPushButton('Cancel',self)
                self.btnCancel.setToolTip('Cancel.')
                self.btnCancel.setFixedWidth(130)
                self.btnCancel.clicked.connect(self.close)


                self.btnAc = QtWidgets.QPushButton('Analyzer configuration',self)
                self.btnAc.setToolTip('Configure the analyzer.')
                self.btnAc.setFixedWidth(150)
                self.btnAc.clicked.connect(self.btnAnalyzerConfig)
                
                layout.addWidget(lblCstEditor,0,0)

                layout.addWidget(lblStartAdr,1,0)
                layout.addWidget(self.ipStartAdr,1,1)
                
                layout.addWidget(lblEndAdr,2,0)
                layout.addWidget(self.ipEndAdr,2,1)

                layout.addWidget(rbRegisters,3,0)
                layout.addWidget(self.cbRegisters,3,1)

                layout.addWidget(rbMemory,4,0)
                layout.addWidget(self.ipMemory,4,1)

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


#---------------------------------------------------------------------------------------------
# GDT Editor Form 

class GDTEditorForm_t(QtWidgets.QDialog):

        def btnOKHandler(self):
                self.accept()

        def btnCancelHandler(self):
                self.reject()

        def __init__(self,parent):
                super(GDTEditorForm_t,self).__init__(parent)
                
                # Get config ini file 
                #hlpConfig = HelperConfigIniFile()
                self.currentConfig = ConfigParser.ConfigParser()
                self.currentConfig.read(hlpConfig.config_ini_path)


                # Main table 
                self.table = QtWidgets.QTableWidget() 
                # 2 columun 
                self.table.setColumnCount(2)

                self.table.setRowCount(len(self.currentConfig.options('GDT')))

                self.table.setHorizontalHeaderItem(0,QtWidgets.QTableWidgetItem("GDT"))
                self.table.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem("Value"))

                # Fill the table with GDT section 
                index = 0 
                for gdt in self.currentConfig.options('GDT'):
                        item = QtWidgets.QTableWidgetItem(gdt)
                        # setItem(row, column,item)
                        self.table.setItem(index, 0, item)
                        index+=1

                index = 0 
                for gdt in self.currentConfig.options('GDT'):
                        item = QtWidgets.QTableWidgetItem(self.currentConfig.get('GDT', gdt ))
                        # setItem(row, column,item)
                        self.table.setItem(index, 1, item)
                        index+=1


                self.table.setColumnWidth(0, 80)
                self.table.setColumnWidth(1, 160)

                self.table.setMaximumWidth(300)
                self.table.setMinimumWidth(300)
                self.table.setMaximumHeight(400)
                self.table.setMinimumHeight(400)

                layout = QtWidgets.QGridLayout()

                layout.addWidget(self.table,0,0)
                #label = QtWidgets.QLabel('Tainting :')
                #layout.addWidget(label,0,0)



                # OK and Cancel button 
                self.btnOK = QtWidgets.QPushButton('OK',self)
                self.btnOK.setToolTip('Save GDT.')
                self.btnOK.setFixedWidth(150)
                self.btnOK.clicked.connect(self.btnOKHandler)


                self.btnCancel = QtWidgets.QPushButton('Cancel',self)
                self.btnCancel.setToolTip('Cancel.')
                self.btnCancel.setFixedWidth(150)
                self.btnCancel.clicked.connect(self.close)


                layout.addWidget(self.btnOK,1,0)
                layout.addWidget(self.btnCancel,1,1)


                layout.setColumnStretch(0,1)
                layout.setRowStretch(2,1)

                self.setLayout(layout)

        def show(self):
                self.setFixedSize(460,500)
                self.setWindowTitle(" GDT Editor : ")
                super(GDTEditorForm_t,self).show()

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

        def btnGDTHandler(self):
                GdtEdit = GDTEditorForm_t(self)
                GdtEdit.show()

        def btnImportHandler(self):
                idaapi.msg("TODO")

        def btnSegsHandler(self):
                idaapi.msg("TODO")

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

                # mode
                lblmode = QtWidgets.QLabel(" mode : ") 
                layout.addWidget(lblmode,6,0)
                self.ipmode = QtWidgets.QLineEdit(self)

                self.ipmode.setText(self.currentConfig.get('settings','mode'))
                self.ipmode.setMaxLength = 256
                self.ipmode.setFixedWidth(200) 
                
                layout.addWidget(self.ipmode,6,1)

                # loader label 
                lblLoader = QtWidgets.QLabel("[Loader] : ")
                layout.addWidget(lblLoader,7,0)


                # rva-code-start 
                lblrvacs = QtWidgets.QLabel(" rva-code : ") 
                layout.addWidget(lblrvacs,10,0)
                self.iptrvacs = QtWidgets.QLineEdit(self)

                self.iptrvacs.setText(self.currentConfig.get('loader','rva-code'))
                self.iptrvacs.setMaxLength = 256
                self.iptrvacs.setFixedWidth(200) 
                
                layout.addWidget(self.iptrvacs,10,1)
                

                # rva-entrypoint 
                lblrvaep = QtWidgets.QLabel(" entrypoint : ") 
                layout.addWidget(lblrvaep,12,0)
                self.iptrvaep = QtWidgets.QLineEdit(self)

                self.iptrvaep.setText(self.currentConfig.get('loader','entrypoint'))
                self.iptrvaep.setMaxLength = 256
                self.iptrvaep.setFixedWidth(200) 
                
                layout.addWidget(self.iptrvaep,12,1)


                # Segments
                lblSegs = QtWidgets.QLabel("[Segments] : ")
                layout.addWidget(lblSegs,13,0)

                self.btnSegsEdit = QtWidgets.QPushButton('Edit/View Segments ',self)
                self.btnSegsEdit.clicked.connect(self.btnSegsHandler)
                layout.addWidget(self.btnSegsEdit,13,1)


                # Binary label 
                lblBinary = QtWidgets.QLabel("[Binary] : ")
                layout.addWidget(lblBinary,14,0)

                # filepath 
                lblfilepath = QtWidgets.QLabel(" filepath : ") 
                layout.addWidget(lblfilepath,15,0)
                self.iptfp = QtWidgets.QLineEdit(self)

                self.iptfp.setText(self.currentConfig.get('binary','filepath'))
                self.iptfp.setMaxLength = 256
                self.iptfp.setFixedWidth(200) 
                
                layout.addWidget(self.iptfp,15,1)

                # format 
                lblformat = QtWidgets.QLabel(" format : ") 
                layout.addWidget(lblformat,16,0)
                self.iptfmt = QtWidgets.QLineEdit(self)

                self.iptfmt.setText(self.currentConfig.get('binary','format'))
                self.iptfmt.setMaxLength = 256
                self.iptfmt.setFixedWidth(200) 
                
                layout.addWidget(self.iptfmt,16,1)

                # code section phys start adr  
                lblpc = QtWidgets.QLabel(" phys-code-addr : ") 
                layout.addWidget(lblpc,17,0)
                self.iptpc = QtWidgets.QLineEdit(self)

                self.iptpc.setText(self.currentConfig.get('loader','phys-code-addr'))
                self.iptpc.setMaxLength = 256
                self.iptpc.setFixedWidth(200) 
                
                layout.addWidget(self.iptpc,17,1)

                # analyzer label 
                lblBinary = QtWidgets.QLabel("[Analyzer] : ")
                layout.addWidget(lblBinary,18,0)

                # unroll 
                lblur = QtWidgets.QLabel(" unroll : ") 
                layout.addWidget(lblur,19,0)
                self.iptur = QtWidgets.QLineEdit(self)

                self.iptur.setText(self.currentConfig.get('analyzer','unroll'))
                self.iptur.setMaxLength = 256
                self.iptur.setFixedWidth(200) 
                
                layout.addWidget(self.iptur,19,1)

                # State label 
                lblstate = QtWidgets.QLabel("[State] : ")
                layout.addWidget(lblstate,20,0)

                self.btnConstrainte = QtWidgets.QPushButton('Define tainting constraints',self)
                self.btnConstrainte.clicked.connect(self.btnCstrHandler)
                layout.addWidget(self.btnConstrainte,20,1)

                # Import table
                lblimport = QtWidgets.QLabel("[Imports] : ")
                layout.addWidget(lblimport,21,0)

                self.btnImportEdit = QtWidgets.QPushButton('Edit/View imports ',self)
                self.btnImportEdit.clicked.connect(self.btnImportHandler)
                layout.addWidget(self.btnImportEdit,21,1)



                # GDT label 
                lblgdt = QtWidgets.QLabel("[GDT] : ")
                layout.addWidget(lblgdt,22,0)

                self.btnGDTEdit = QtWidgets.QPushButton('Edit/View GDT ',self)
                self.btnGDTEdit.clicked.connect(self.btnGDTHandler)
                layout.addWidget(self.btnGDTEdit,22,1)

                # OK and cancel button 
                self.btnOK = QtWidgets.QPushButton('OK',self)
                self.btnOK.clicked.connect(self.btnOKHandler)
                layout.addWidget(self.btnOK,25,0)

                self.btnCancel = QtWidgets.QPushButton('Cancel',self)
                self.btnCancel.clicked.connect(self.btnCancelHandler)
                layout.addWidget(self.btnCancel,25,1)
                

                # Setting the layout 
                layout.setColumnStretch(4,1)
                layout.setRowStretch(26,1)
                self.setLayout(layout)
                


        def show(self):
                # width x height
                self.setFixedSize(350,600)
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
                BinCATLogViewer.Log("[*] Analyzer :  starting process \n",SCOLOR_DNAME)


        def procanalyzer_on_finish(self):
                idaapi.msg(" [+] Analyzer process terminated \n") 
                # get the result.txt file and parse it 
                resultfile = GetIdbDir()+"result.txt"  

                BinCATLogViewer.Log("[+] BinCAT : Parsing analyzer result file \n",SCOLOR_LOCNAME)
                currentState = analyzer_state.AnalyzerState()
                AnalyzerStates = currentState    
                
                AnalyzerStates.setStatesFromAnalyzerOutput(resultfile)
                keys  = AnalyzerStates.stateAtEip.keys()
                for  key in keys :
                        idaapi.msg(" States addresses 0x%08x \n"%( int(key.address) ))


                

                # update the BinCATTaintedForm with the first state (nodeid=0)
                idaapi.msg(" type(taintingview) = %s \n "%(type(BinCATTaintedForm)))

                rc = BinCATTaintedForm.tablereg.rowCount()
                for i in range(0,rc):
                        BinCATTaintedForm.tablereg.removeRow(i)

                BinCATTaintedForm.tablereg.setRowCount(0)
                rc = BinCATTaintedForm.tablereg.rowCount()
                # display only node 0 that corresponds to the start address state
                for  key in keys :
                        state = AnalyzerStates.getStateAt(key.address)
                        if state.nodeid == "0":
                                BinCATTaintedForm.nilabel.setText('Node Id : '+state.nodeid) 
                                BinCATTaintedForm.alabel.setText('RVA address : '+hex(int(key.address))) 
                                for k , v  in state.ptrs.iteritems():
                                        if k == "mem":
                                                pass
                                        if k == "reg":
                                                for i , j in v.iteritems():
                                                        if isinstance(j,analyzer_state.ConcretePtrValue):
                                                                BinCATTaintedForm.tablereg.insertRow(rc)
                                                                item = QtWidgets.QTableWidgetItem(i)
                                                                BinCATTaintedForm.tablereg.setItem(rc, 0, item)
                                                                item = QtWidgets.QTableWidgetItem(hex(int(j.address)))
                                                                BinCATTaintedForm.tablereg.setItem(rc, 2, item)
                                                                rc+=1
                                                        if isinstance(j,analyzer_state.AbstractPtrValue):
                                                                pass

        # for a first test I use this callback to get analyzer output 
        # the goal is exchange information using a qtcpsocket
        def procanalyzer_on_out(self):
		idaapi.msg(" [+] procanalyzer_on_out ")
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
                self.Refresh()
                

# ----------------------------------------------------------------------------------------------
# BinCAT Tainted values form 
# This form containes the values of tainted registers and memory 

class BinCATTaintedForm_t(PluginForm):

        def OnCreate(self,form):
                BinCATLogViewer.Log("[+] BinCAT Creating Tainted form ",SCOLOR_LOCNAME)
                
                # Get parent widget 
                self.parent = self.FormToPyQtWidget(form)
                self.registers_x86 = ['EAX','EBX','ECX','EDX','ESI','EDI','ESP','EBP']
                layout = QtWidgets.QGridLayout()
                self.tablereg = QtWidgets.QTableWidget() 
                
                #Node id label 
                self.nilabel = QtWidgets.QLabel('Node Id :')
                layout.addWidget(self.nilabel,0,0)


                #RVA address label 
                self.alabel = QtWidgets.QLabel('RVA address :')
                layout.addWidget(self.alabel,1,0)


                # Main table 
                self.tablereg.setColumnCount(3)
                #self.table.setRowCount(len(self.registers_x86))

                self.tablereg.setHorizontalHeaderItem(0,QtWidgets.QTableWidgetItem("Registers"))
                self.tablereg.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem("Tainted"))
                self.tablereg.setHorizontalHeaderItem(2,QtWidgets.QTableWidgetItem("Values"))

                self.tablereg.setColumnWidth(0, 80)
                self.tablereg.setColumnWidth(1, 80)
                self.tablereg.setColumnWidth(2, 100)


                self.tablereg.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
                self.tablereg.verticalHeader().setDefaultSectionSize(15)

                layout.addWidget(self.tablereg,2,0)

                layout.setColumnStretch(0,1)
                layout.setRowStretch(3,1)

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
                inifile = GetIdbDir()+"nop.ini"
                outfile = GetIdbDir()+"result.txt"
		logfile = GetIdbDir()+"logfile.txt"

                cmdline = "%s %s --inifile %s --outfile %s --logfile %s" % (
                                os.path.join(PYTHON_PATH,PYTHON_BIN),analyzerpath,inifile,outfile,logfile)  

                # create Analyzer Object 
                self.analyzer = Analyzer() 
                
                # start the process 
                try :

                	idaapi.msg(" [+] BinCAT : Analyzer cmdline is :\n  %s \n "%cmdline)
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
                #idaview = PluginForm.FormToPyQtWidget(get_tform_idaview(ctx.form))
                f = idaapi.find_tform("IDA View-Tainting View")        
                idaview = PluginForm.FormToPyQtWidget(f)
                AnalyzerLauncher = TaintLaunchForm_t(idaview)
                #AnalyzerLauncher = Toto_t(idaview)
                AnalyzerLauncher.exec_()
                
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
        global registers_x86          
        global BinCATForm
        global BinCATLogViewer
        global hlpConfig
        global hooks
        global BinCATTaintedForm
        global AnalyzerStates
        try:
                BinCATForm
                BinCATLogViewer
                BinCATTaintedForm 
        except:
                BinCATForm = BinCATForm_t() 
                BinCATLogViewer = BinCATLog_t()
                BinCATTaintedForm = BinCATTaintedForm_t() 


        AnalyzerStates = analyzer_state.AnalyzerState()

        idaapi.msg("[+] BinCAT Starting main form\n")
        if BinCATLogViewer.Create(1):
                BinCATLogViewer.Show()
                idaapi.set_dock_pos("BinCAT Log viewer","Output window",idaapi.DP_LEFT) 
                BinCATLogViewer.Log("[+] BinCAT Starting main form",SCOLOR_LOCNAME)
        
        BinCATForm.Show()
        BinCATTaintedForm.Show()
        # TODO : get the list of registers from IDA depending on the current cpu arch  
        registers_x86 = ['EAX','EBX','ECX','EDX','ESI','EDI','ESP','EBP']
           

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
