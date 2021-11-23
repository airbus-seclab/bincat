#!/usr/bin/env python3
import collections

def main():
    from pybincat import mlbincat
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("inputfile",
                        help="Input state file")
    parser.add_argument("outputfile",
                        help="file to output computed states into")
    parser.add_argument("logfile",
                        help="log file")
    parser.add_argument(
        "--diff", "-d", nargs=2, metavar=('NODEID1', 'NODEID2'),
        help="Display diff between 2 node ids")
    parser.add_argument(
        "--first-uncertain-taint", action='store_true',
        help="Display where taint is uncertain for the first time")

    options = parser.parse_args()

    from pybincat import cfa
    p = cfa.CFA.from_filenames(options.inputfile, options.outputfile,
                               options.logfile)

    if options.diff:
        # fetch states
        try:
            state1 = p[options.diff[0]]
        except KeyError:
            logger.error("No State is defined having node_id %s", options.diff[0])
            sys.exit(1)
        try:
            state2 = p[options.diff[1]]
        except KeyError:
            logger.error("No State is defined having node_id %s", options.diff[1])
            sys.exit(1)
        print((state1.diff(state2)))

    if options.first_uncertain_taint:
        state, tainted = find_first_tainted_node(p)
        if state:
            print(("%s is tainted:" % state))
            for (reg, val) in tainted:
                print(("%s -> %s" % (reg, val)))
        else:
            print("No state containing tainted values have been found.")

def find_first_tainted_node(p):
        node0 = "0"
        nextstates = collections.deque()
        nextstates.append(node0)
        tainted = []
        while nextstates:
            curstate = p[nextstates.popleft()]
            nextstates.extend(p.edges[curstate.node_id])
            for reg, vals in list(curstate.regaddrs.items()):
                for val in vals:
                    if val.ttop != 0 or val.tbot != 0:
                        tainted.append((reg, vals))
                        break
            if tainted:
                return curstate, tainted
        return None, None


if __name__ == "__main__":
    main()
