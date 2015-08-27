#!/usr/bin/python 


#Imports
from idaapi import * 
from idc import * 
from idautils import *
import threading 
import time
import socket 
import os 
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
    
    for i in range(0,GetEntryPoinQty()):
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


# Classes 


class BinCATThread (threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    
    def run(self):
        print(" [+] Starting %s ")%(self.name)
        #print_time(self.name, self.counter, 5)
        try: 
            parent , child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)  
            pid  = os.fork() 
            if pid : # IDA 
                parent.close() 
                message = " toto "
                print("[+] IDA plugin --> analyzer : %s")%message
                child.send(message) 
                fileinfo = GetFileInfo()
                print(fileinfo)
                message = child.recv(1024)
                print("[+] message received from analyzer %s ")%message   

            else :  # Analyzer 
                child.close() 
                fd = parent.fileno() 
                #print("[+] IDA plugin launching analyzer.py ")
                os.execv('/opt/ida-6.7/python/mymodule/analyzer.py',['Bincat','123456' ,'--commandfd', str(fd)])
        except : 
            raise      

        print(" [+] Exiting %s ")%self.name




def main():
    print("BinCAT module loaded")
    if not idaapi.get_root_filename():                                                               
        print "[sync] please load a file/idb before"
        return
    
    thread1 = BinCATThread(1, "Thread-1", 1)
    #thread2 = BinCATThread(2, "Thread-2", 2)

    thread1.start() 
    #thread2.start()

    print(" [+] Exiting main thread ")

main()
