#!/usr/bin/python 
# Filename : mymodule.py 

#Imports
from idaapi import * 
from idc import * 
from idautils import *
from analyseur import Analyseur

# Functions 
def test():
    print("This is an IDA test Module")
    x = Analyseur() 
    x.test()



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

