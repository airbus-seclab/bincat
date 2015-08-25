#!/usr/bin/python 

# Imports 
import argparse
import socket 


'''
Purpose of this class is to simulate the analyzer 
'''



class Analyzer:
    def __init__(self):
        version = "[+] analyzer stub"


    def test(self,fd ):
        print("[+] Analyzer stub ! ")
        analyzer_socket = socket.fromfd( fd, socket.AF_UNIX, socket.SOCK_DGRAM) 
        message = analyzer_socket.recv(1024)      
        print("Analyzer received message %s")%message
        message="Ok "+message
        analyzer_socket.send(message)        


    def printInput(self, address , mnemonics , opcodes ):
        print("[+] Analyzer has received the following paramaters : " )

def main():
    print("[+] Launching Analyzer : ")
    a = Analyzer() 
    
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
