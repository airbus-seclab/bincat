#!/usr/bin/python2
# Imports
import os
import logging
import argparse
import sys


def main():
    logging.basicConfig()
    logger = logging.getLogger('BinCAT Analyzer')
    # analyzer_dir = os.path.dirname(sys.argv[0]) + '/analyzer_log.txt'

    # logfile = logging.FileHandler(analyzer_dir)
    # formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s    ')

    # logfile.setFormatter(formatter)
    # logger.addHandler(logfile)

    parser = argparse.ArgumentParser(
        description="Analyzer arguments parsing")
    parser.add_argument(
        '--inifile', '-i', type=str, help='Analyzer configuration file',
        required=True)
    parser.add_argument(
        '--outfile', '-o', type=str, help='Analyzer output file',
        required=True)
    parser.add_argument(
        '--logfile', '-l', type=str, help='Analyzer log file', required=True)
    parser.add_argument(
        "--diff", "-d", nargs=2, metavar=('NODEID1', 'NODEID2'),
        help="Display diff between 2 states")
    parser.add_argument(
        "--verbose", "-v", action="count", default=0,
        help="Be more verbose (can be used several times).")

    args = parser.parse_args()

    logging.basicConfig(format="%(levelname)-5s: %(message)s",
                        level=max(1, 30-10*args.verbose))

    # default: WARNING (30), -v once to reach INFO (20)
    logger.setLevel(max(1, 30-10*args.verbose))

    logger.info("[Analyzer] Parsing command line:")
    logger.info("[Analyzer] ini file: %s ", args.inifile)
    logger.info("[Analyzer] out file: %s ", args.outfile)
    logger.info("[Analyzer] log file: %s ", args.logfile)

    from pybincat import program

    p = program.Program.from_filenames(args.inifile, args.outfile,
                                       args.logfile)

    if args.diff:
        # fetch states
        try:
            state1 = p.states[p.nodes[args.diff[0]]]
        except KeyError:
            logger.error("Node id %s does not exist", args.diff[0])
            sys.exit(1)
        try:
            state2 = p.states[p.nodes[args.diff[1]]]
        except KeyError:
            logger.error("Node id %s does not exist", args.diff[0])
            sys.exit(1)
        print state1.diff(state2)


if __name__ == '__main__':
    main()
