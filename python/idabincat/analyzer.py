#!/usr/bin/python 

# Imports 
import os 
import logging 
import argparse
import socket 
import cPickle 
import sys 
import ConfigParser
'''
le module mlbincat --> /usr/lib/libbincat.so 
'''
import mlbincat 


'''
Purpose of this class is to simulate the analyzer 
'''

class Analyzer:
    def __init__(self):
        version = "[+] Analyzer::__init__ function"
        self.logger  =  logging.getLogger('BinCAT Analyzer')
        #analyzer_dir =  os.getcwd() + '/analyzer_log.txt' 
        self.analyzer_dir =  os.path.dirname(sys.argv[0]) + '/analyzer_log.txt' 
        # print(analyzer_dir)
        self.logfile =  logging.FileHandler(self.analyzer_dir)
        self.formatter =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        self.logfile.setFormatter(self.formatter)
        self.logger.addHandler(self.logfile)
        self.logger.setLevel(logging.INFO)
        self.config =  ConfigParser.RawConfigParser() 
        self.analyzer_socket = -1 


    def initSocketFromFd(self,fd): 
        # creation de la socket 
        self.logger.info("[Analyzer] Initializing analyzer socket")
        self.analyzer_socket = socket.fromfd( fd, socket.AF_UNIX, socket.SOCK_DGRAM)
        self.logger.info("[Analyzer] socket.fromfd() ") 
        message="[Analyzer] socket correctly created " 
        self.analyzer_socket.send(message)        
       


    def TestParseConfigFile(self,filename):
        # function to parse analyzer_config.ini file
        self.logger.info("[Analyzer] TestParseConfigFile")
        self.config.read(filename)
        self.logger.info('[Analyzer] %s configuration file read ',filename)
                
        return (self.config.items('settings'))                

    def test(self):
        message = self.analyzer_socket.recv(1024)      
        self.logger.info("[Analyzer] Analyzer received message %s",message)
       
        message = os.path.dirname(sys.argv[0]) + "/" + message  
        result = self.TestParseConfigFile(message)
        message=""
        for k,v in result:
            message +=  k+" = "+v+"\n"
        message="[Ok] : \n" + message  
        self.analyzer_socket.send(message)        
        self.logger.info("[Analyzer] Analyzer sent message  %s",message)

    def printInput(self, address , mnemonics , opcodes ):
        print("[+] Analyzer has received the following paramaters : " )

# Cette fonction permet de lancer le stub Ocaml
    def LaunchOcaml(self,inifile,outfile):
        self.logger.info("[Analyzer] Launching OCaml stub")
        try: 
            mlbincat.process(inifile, outfile) 
        except Exception,e:
            error = "[Analyzer] Exception when launching Ocaml stub (%s)"%e 
            self.logger.info(error)
            self.analyzer_socket.send(error)        

        
        

def main():
    
    a = Analyzer() 
    a.logger.info("[Analyzer] Launching Analyzer main function : ")
    print("\n[*] Analyzer : Entering main function. \n")
    argsParser = argparse.ArgumentParser(description="Analyzer arguments parsing . ")
    argsParser.add_argument('address' ,action='store' ,help ='offset in the binary')
    argsParser.add_argument('--mnemonics' ,action='store' ,help ='mnemonics to analyze')
    argsParser.add_argument('--opcode(s)' ,action='store' ,help ='opcodes to analyze')
    argsParser.add_argument('--commandfd' ,action='store' ,help ='file descriptor')
    argsParser.add_argument('--inifile' ,action='store' ,help ='rule ini file')
    argsParser.add_argument('--outfile' ,action='store' ,help ='output file')


    
    args = argsParser.parse_args()
    a.logger.info("[Analyzer] Parsing command line: ")
    a.logger.info("[Analyzer] ini file : %s ",args.inifile)
    a.logger.info("[Analyzer] out file : %s ",args.outfile)

    print("[*] Analyzer : treatement of the following parameters:\n")
    print(" - address : %s.\n"%args.address)
    print(" - inifile : %s.\n"%args.inifile)
    print(" - outfile : %s.\n"%args.outfile)
   

    # create socket 
    a.logger.info("[Analyzer] Creating Socket from IDA fd ")
    #a.initSocketFromFd(int(args.commandfd))

    if  ( args.inifile and args.outfile ):
        a.LaunchOcaml(args.inifile,args.outfile) 

    
    print(args.address)
    print(args.commandfd)
    #a.test() 





main()
