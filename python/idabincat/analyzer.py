#!/usr/bin/python2
# Imports
import os
import logging
import argparse
import sys


def main():
    logger = logging.getLogger('BinCAT Analyzer')
    analyzer_dir = os.path.dirname(sys.argv[0]) + '/analyzer_log.txt'

    logfile = logging.FileHandler(analyzer_dir)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s    ')

    logfile.setFormatter(formatter)
    logger.addHandler(logfile)

    argsParser = argparse.ArgumentParser(
        description="Analyzer arguments parsing")
    argsParser.add_argument(
        '--inifile', '-i', type=str, help='Analyzer configuration file',
        required=True)
    argsParser.add_argument(
        '--outfile', '-o', type=str, help='Analyzer output file',
        required=True)
    argsParser.add_argument(
        '--logfile', '-l', type=str, help='Analyzer log file', required=True)
    argsParser.add_argument(
        "--verbose", "-v", action="count", default=0,
        help="Be more verbose (can be used several times).")

    args = argsParser.parse_args()

    # default: WARNING (30), -v once to reach INFO (20)
    logger.setLevel(max(1, 30-10*args.verbose))

    logger.info("[Analyzer] Parsing command line:")
    logger.info("[Analyzer] ini file: %s ", args.inifile)
    logger.info("[Analyzer] out file: %s ", args.outfile)
    logger.info("[Analyzer] log file: %s ", args.logfile)

    from pybincat import program

    p = program.Program.from_filenames(args.inifile, args.outfile,
                                       args.logfile)


if __name__ == '__main__':
    main()
