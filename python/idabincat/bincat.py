#!/usr/bin/python 


#Imports
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

exitFlag =0 

# Functions 
def test():
    print("This is an IDA test Module")
    x = Analyszer() 
    x.test()



def print_time(threadName, delay, counter):
    while counter:
        if exitFlag:
            thread.exit()
        time.sleep(delay)
        print "%s: %s" % (threadName, time.ctime(time.time()))
        counter -= 1


def getCurrentaddress() : 
    print("Current address is : %s")%(hex(here()).rstrip('L'))
     

def getAllfunctions() :
    print("Listing all functions ")
    # idautils necessary 
    ea = ScreenEA() 
    for funcea in Functions(SegStart(ea),SegEnd(ea)):
        print("Function %s at 0x%x")%(GetFunctionName(funcea),funcea)


'''
AddComment
params : address format hex (0xFF...)
          string : commentaire 
'''

def AddComment( address  , string  ) :
     # check that input address is in format : 0xXXXX
     MakeComm(address, string)                                                                    

'''
Params : No 
Return : an OrderedDict that contains the following informations 
         filename : 
         imagebase 
         entrypoints (name , address )
         segments  (name , start address, end address, class )
'''
def GetFileInfo() :
    ordinals =  [] 
    entrypoints = []
    main_entry_point_adr = 0x00
    main_entry_point_name = "" 
    
    for i in range(0,GetEntryPointQty()):
        ordinals.append(GetEntryOrdinal(i))

    for i in ordinals:
        entrypoints.append( (i,GetEntryPoint(i)) ) 

    for i in entrypoints:
        if GetFunctionName(i[0]) == "start":
            main_entry_point_adr =  hex(i[1]).rstrip('L')
            main_entry_point_name= "start" 
 

    data_to_send["filename"] = idaapi.get_root_filename()
    data_to_send["imagebase"] = idaapi.get_imagebase() 
    data_to_send["entrypoints"] = (main_entry_point_name,main_entry_point_adr)


    i = 0 
    for seg in Segments():
        seg_attributes = idc.GetSegmentAttr(SegStart(seg),idc.SEGATTR_TYPE)
        if seg_attributes  == idaapi.SEG_NORM : data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"UNKNOWN_TYPE")
        if seg_attributes  == idaapi.SEG_XTRN : data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"EXTERN")
        if seg_attributes  == idaapi.SEG_CODE : data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"CODE")
        if seg_attributes  == idaapi.SEG_DATA : data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"DATA")
        if seg_attributes  == idaapi.SEG_IMP :  data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"JAVA_IMPLEMENTATION")
        if seg_attributes  == idaapi.SEG_GRP :  data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"GROUP_SEGMENTS")
        if seg_attributes  == idaapi.SEG_NULL : data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"ZERO_LEN")
        if seg_attributes  == idaapi.SEG_UNDF : data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"UNDEFINED_SEGMENT")
        if seg_attributes  == idaapi.SEG_BSS :  data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"BSS")
        if seg_attributes  == idaapi.SEG_ABSSYM : data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"SEGMENT_WITH_ABSOLUTE_SYMBOLS")
        if seg_attributes  == idaapi.SEG_COMM :   data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"SEGMENT_WITH_COMMUNAL_DEFS")
        if seg_attributes  == idaapi.SEG_IMEM :  data_to_send["segment_"+str(i)] = ( SegName(seg), hex(SegStart(seg)).rstrip('L'), hex(SegEnd(seg)).rstrip('L')  ,"IDA_INTERN")
        i+=1

    return(data_to_send)

'''
function to get the memory model basing on IDA database properties

'''
def getMemoryModel():
    ida_db_info_structure = idaapi.get_inf_structure() 
    compiler_info =  ida_db_info_structure.cc 
    if  (compiler_info.cm & idaapi.C_PC_TINY == 1): return "tiny"
    if  (compiler_info.cm & idaapi.C_PC_SMALL == 1): return "small"
    if  (compiler_info.cm & idaapi.C_PC_COMPACT == 1): return "compact"
    if  (compiler_info.cm & idaapi.C_PC_MEDIUM == 1): return "medium"
    if  (compiler_info.cm & idaapi.C_PC_LARGE == 1): return "large"
    if  (compiler_info.cm & idaapi.C_PC_HUGE == 1): return "huge"
    if  (compiler_info.cm & idaapi.C_PC_FLAT == 1 ): return "flat"


'''
get the call convention
'''

def getCallConvention():
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


'''
get pointer size for memsz 
'''    
def getPointerSize():
    ida_db_info_structure = idaapi.get_inf_structure() 
    compiler_info =  ida_db_info_structure.cc 
    if  (compiler_info.cm & CM_MASK ) == CM_UNKNOWN : return "unknown"
    if  ( (compiler_info.cm & CM_MASK ) == CM_N8_F16) and (compiler_info.size_i < 2 ): return "16"
    if  ( (compiler_info.cm & CM_MASK ) == CM_N64) and (compiler_info.size_i > 2 ) : return "64"
    if  (compiler_info.cm & CM_MASK ) == CM_N16_F32 : return "32"
    if  (compiler_info.cm & CM_MASK ) == CM_N32_F48 : return "48"

class BinCATThread(threading.Thread):

     def __init__(self,msg):
         threading.Thread.__init__(self)
         self.msg = msg 
         self.config_ini_file = 'analyzer_config.ini' 
         self.config_ini_path  = '' 
     '''
     function test de generation d'un fichier de config pour l'analyseur

     '''
     def TestGenerateConfigFile(self):
         config  =  ConfigParser.RawConfigParser() 
         config.add_section('settings')
         config.set('settings','memmodel',getMemoryModel()) 
         config.set('settings','callconv',getCallConvention())
         # pointer size 
         config.set('settings','address_size',getPointerSize())
         # confi ini file should be in the same directriy as bincat.py and analyzer 
         self.config_ini_path = GetIdaDirectory() + '/python/mymodule/' + self.config_ini_file         
         # writing configuration file
         idaapi.msg("[BinCAT] BinCATThread::TestGenerateConfigFile opening config file %s \n"%self.config_ini_path) 
         with open(self.config_ini_path,'w') as configfile:
             config.write(configfile)
     
     def run(self):
         parent , child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)  
         fdnum = child.fileno() 
         proc_analyzer= subprocess.Popen(['/opt/ida-6.7/python/mymodule/analyzer.py', '123456' ,'--commandfd', str(fdnum)],stdout=1)
         # generate confg ini file 
         self.TestGenerateConfigFile() 
         idaapi.msg("[BinCAT] BinCATThread::TestGenerateConfigFile()\n")
         #idaapi.msg("Analyzer debug messages %s \n"%analyzer_debug)
         parent.send(self.config_ini_file)
         #child.close()
         idaapi.msg("Analyzer response is %s\n"%parent.recv(1000)) 

       


def main():
    idaapi.msg("BinCAT module loaded\n")
    if not idaapi.get_root_filename():                                                               
        idaapi.msg("[BinCAT] please load a file/idb before \n")
        return
    idaapi.msg("[BinCAT] Launching bincat thread to communicate with the analyzer\n")
    bincat_thread = BinCATThread("message 1")
    bincat_thread.start()
    

    #bincat_thread = BinCATThread("message 2")
    #bincat_thread.start()
    







main()
