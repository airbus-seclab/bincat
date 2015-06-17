
#testing socketpair

#!/usr/bin/python 

import socket 
import os


try : 
    parent , child  = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = os.fork() 
    if pid : # child 
        parent.close() 
        message  = "child : I'm sending you a message"
        child.send(message) 
        print("child --> parent :  %s : ")%message 
        message  =  child.recv(1024) 
        print("child <-- parent %s : ")%message
    else : # parent 
        child.close() 
        message =  parent.recv(1024)
        print("parent <-- child  %s : ")%message
        message = "parent : Ok !"
        print("parent --> child %s : ")%message
        parent.send(message) 
        
except:
     raise




