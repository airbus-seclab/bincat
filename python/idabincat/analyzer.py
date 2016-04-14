#!/usr/bin/python 
# Imports 
import os 
import logging 
import argparse
import socket 
import cPickle 
import sys 
import ConfigParser
#import analyzer_state
'''
le module mlbincat --> /usr/lib/libbincat.so 
'''

        

def main():
    logger  =  logging.getLogger('BinCAT Analyzer') 
    analyzer_dir =  os.path.dirname(sys.argv[0]) + '/analyzer_log.txt'

    print(analyzer_dir)

    logfile =  logging.FileHandler(analyzer_dir)
    formatter =  logging.Formatter('%(asctime)s %(levelname)s %(message)s    ')
    
    logfile.setFormatter(formatter)
    logger.addHandler(logfile)
    logger.setLevel(logging.INFO)


    print("\n[*] Analyzer : Entering main function. \n")
    argsParser = argparse.ArgumentParser(description="Analyzer arguments parsing . ")
    argsParser.add_argument('--inifile' ,action='store' ,help ='Analyzer configuration file ')
    argsParser.add_argument('--outfile' ,action='store' ,help ='Analyzer output file')
    argsParser.add_argument('--logfile' ,action='store' ,help ='Analyzer log file ')


    
    args = argsParser.parse_args()

    logger.info("[Analyzer] Parsing command line:") 
    logger.info("[Analyzer] ini file : %s ",args.inifile)
    logger.info("[Analyzer] out file : %s ",args.outfile)
    logger.info("[Analyzer] log file : %s ",args.logfile)

    print("[*] Analyzer : processing the following parameters:\n")
    print(" - inifile : %s.\n"%args.inifile)
    print(" - outfile : %s.\n"%args.outfile)
    print(" - logfile : %s.\n"%args.logfile)
   
    import analyzer_state

    a = analyzer_state.AnalyzerState()
    ac = a.run_analyzer(args.inifile,args.outfile,args.logfile) 
    keys  = ac.stateAtEip.keys()
    print("---- Taint analysis results ------\n")
    for  key in keys :
        state = ac.getStateAt(key.address)
        print("----------------------------------\n")
        print("Node id : %s - Rva : %s \n"  %(state.nodeid,hex(key.address).rstrip('L'))  )
        for k , v  in state.ptrs.iteritems():
             print("%s :  \n"%k)
             if k == "mem":
                 for x , y  in v.iteritems():
                     if isinstance(x,analyzer_state.ConcretePtrValue):
                         print("mem [0x%08x] = %s   \n"%(int(x.address),x.region))
                     if isinstance(j,analyzer_state.ConcretePtrValue):
                         print("reg[%s] = (%s , 0x%08x ) \n"%(i,j.region, int(j.address) ) )
                     if isinstance(y,analyzer_state.ConcretePtrValue):
                         print("mem [0x%08x] = %s   \n"%(int(y.address),y.region))
                     if isinstance(x,analyzer_state.AbstractPtrValue):
                         print("mem [] = %s   \n"%(x.value))
                     if isinstance(y,analyzer_state.AbstractPtrValue):
                         print("mem [] = %s   \n"%(y.value))

             if k == "reg":
                 for i , j in v.iteritems():
                     if isinstance(j,analyzer_state.ConcretePtrValue):
                         print("reg[%s] = (%s , 0x%08x ) \n"%(i,j.region, int(j.address) ) )
                     if isinstance(j,analyzer_state.AbstractPtrValue):
                         print("reg[%s] = (%s) \n"%(i,j.value) )

                     





main()
