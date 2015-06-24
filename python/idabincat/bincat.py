#!/usr/bin/python 
# Filename : mymodule.py 

#Imports
from idaapi import * 
from idc import * 
from idautils import *
import threading 
import time
import socket 
import os 


exitFlag =0 

# Functions 
def test():
    print("This is an IDA test Module")
    x = Analyseur() 
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
AddComment : pour ajouter un commentaire  
params : address format hex (0xFF...)
          string : commentaire 
'''

def AddComment( address  , string  ) :
     # check that input address is in format : 0xXXXX
     MakeComm(address, string)                                                                    


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
                print("[+] IDA plugin --> analyseur : %s")%message
                child.send(message) 
                message = child.recv(1024)
                print("[+] message received from analyseur %s ")%message   

            else :  # Analyseur 
                child.close() 
                fd = parent.fileno() 
                #print("[+] IDA plugin launching analyseur.py ")
                os.execv('/opt/ida-6.7/python/mymodule/analyseur.py',['Bincat','123456' ,'--commandfd', str(fd)])
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
