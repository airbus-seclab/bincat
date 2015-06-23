#/usr/bin/python 

# Imports 
import argparse
import socket 


'''
Cette classe a por objectif de simuler l'analyseur 
'''



class Analyseur:
    def __init__(self):
        version = "[+] analyseur stub"


    def test(self,fd ):
        print("[+] Analyseur stub ! ")
        analyseur_socket = socketfromfd( fd, socket.AF_UNIX, socket.SOCK_DGRAM) 
        message = analyseur_socket.recv(1024)      
        print("Analyseur received message %s")%message
        


    def printInput(self, address , mnemonics , opcodes ):
        print("[+] Analyseur has received the following paramaters : " )

def main():
    print("[+] Launching Analyseur : ")
    a = Analyseur() 
    
    argsParser = argparse.ArgumentParser(description="Analyseur arguments parsing . ")
    argsParser.add_argument('address' ,type=int ,action='store' ,help ='offset in the binary')
    argsParser.add_argument('--mnemonics' ,action='store' ,help ='mnemonics to analyze')
    argsParser.add_argument('--opcode(s)' ,action='store' ,help ='opcodes to analyze')
    argsParser.add_argument('--command-fd' ,action='store' ,help ='file descriptor')

    
    args = argsParser.parse_args()
    a.test(fd) 






main()
