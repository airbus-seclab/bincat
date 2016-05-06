#!/usr/bin/python
# Imports
import os
import logging
import argparse
import sys
# import analyzer_state


def main():
    logger = logging.getLogger('BinCAT Analyzer')
    analyzer_dir = os.path.dirname(sys.argv[0]) + '/analyzer_log.txt'

    print(analyzer_dir)

    logfile = logging.FileHandler(analyzer_dir)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s    ')

    logfile.setFormatter(formatter)
    logger.addHandler(logfile)
    logger.setLevel(logging.INFO)

    print("\n[*] Analyzer: Entering main function. \n")
    argsParser = argparse.ArgumentParser(
        description="Analyzer arguments parsing")
    argsParser.add_argument(
        '--inifile', action='store', help='Analyzer configuration file')
    argsParser.add_argument(
        '--outfile', action='store', help='Analyzer output file')
    argsParser.add_argument(
        '--logfile', action='store', help='Analyzer log file ')

    args = argsParser.parse_args()

    logger.info("[Analyzer] Parsing command line:")
    logger.info("[Analyzer] ini file: %s ", args.inifile)
    logger.info("[Analyzer] out file: %s ", args.outfile)
    logger.info("[Analyzer] log file: %s ", args.logfile)

    print("[*] Analyzer: processing the following parameters:\n")
    print(" - inifile: %s.\n" % args.inifile)
    print(" - outfile: %s.\n" % args.outfile)
    print(" - logfile: %s.\n" % args.logfile)

    from pybincat import state

    a = state.AnalyzerState()
    ac = a.run_analyzer(args.inifile, args.outfile, args.logfile)
    keys = ac.stateAtEip.keys()
    print("---- Taint analysis results ------\n")
    for key in keys:
        state = ac.getStateAt(key.value)
        print("----------------------------------\n")
        print("Node id: %s - Rva: %s \n" %
              (state.nodeid, hex(key.value).rstrip('L')))
        for k, v in state.ptrs.iteritems():
            print("%s: \n" % k)
            if k == "mem":
                for x, y in v.iteritems():
                    if type(x) is str:
                        continue  # XXX
                    if x.is_concrete():
                        print("mem [0x%08x] = %s \n" %
                              (int(x.value), x.region))
                    else:
                        print("mem [] = %s \n" % (x.value))
                    if y.is_concrete():
                        print("mem [0x%08x] = %s \n" %
                              (int(y.value), y.region))
                    else:
                        print("mem [] = %s \n" % (y.value))

            if k == "reg":
                for i, j in v.iteritems():
                    if j.is_concrete():
                        print("reg[%s] = (%s, 0x%08x ) \n" %
                              (i, j.region, int(j.value)))
                    else:
                        print("reg[%s] = (%s) \n" % (i, j.value))


if __name__ == '__main__':
    main()
