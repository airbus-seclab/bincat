#!/usr/bin/python 
print("TOTO")
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

        
f =  open('/tmp/toto','w') 
f.write('test')
f.close()

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
    states = a.run_analyzer(args.inifile,args.outfile,args.logfile) 
    print(states)
    





main()
