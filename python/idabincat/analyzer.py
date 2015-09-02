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
Purpose of this class is to simulate the analyzer 
'''



class Analyzer:
    def __init__(self):
        version = "[+] analyzer stub"
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

    def TestParseConfigFile(self,filename):
        # function to parse analyzer_config.ini file
        self.logger.info("[Analyzer] TestParseConfigFile")
        self.config.read(filename)
        self.logger.info('[Analyzer] %s configuration file read ',filename)
                
        return (self.config.items('settings'))                

    def test(self,fd):
        self.logger.info("[Analyzer] Analyzer stub loaded")
        analyzer_socket = socket.fromfd( fd, socket.AF_UNIX, socket.SOCK_DGRAM)
        self.logger.info("[Analyzer] socket.fromfd()  ok\n") 
        message = analyzer_socket.recv(1024)      
        self.logger.info("[Analyzer] Analyzer received message %s",message)
       
        message = os.path.dirname(sys.argv[0]) + "/" + message  
        result = self.TestParseConfigFile(message)
        message=""
        for k,v in result:
            message +=  k+" = "+v+"\n"
        message="[Ok] : \n" + message  
        analyzer_socket.send(message)        
        self.logger.info("[Analyzer] Analyzer sent message  %s",message)

    def printInput(self, address , mnemonics , opcodes ):
        print("[+] Analyzer has received the following paramaters : " )

def main():
    
    a = Analyzer() 
    a.logger.info("[Analyzer] Launching Analyzer main function : ")
    
    argsParser = argparse.ArgumentParser(description="Analyzer arguments parsing . ")
    argsParser.add_argument('address' ,action='store' ,help ='offset in the binary')
    argsParser.add_argument('--mnemonics' ,action='store' ,help ='mnemonics to analyze')
    argsParser.add_argument('--opcode(s)' ,action='store' ,help ='opcodes to analyze')
    argsParser.add_argument('--commandfd' ,action='store' ,help ='file descriptor')

    
    args = argsParser.parse_args()
    print(args.address)
    print(args.commandfd)
    a.test( int(args.commandfd) ) 






main()
