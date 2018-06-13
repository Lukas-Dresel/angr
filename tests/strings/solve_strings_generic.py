import time
import sys

from strings_helper import *
from eval_utils import dump_sm_stats


proj = setup_project(sys.argv[1])

s, symbolic_input = make_symbolic_state(proj)

sm = proj.factory.simulation_manager(s, save_unsat=True)

start = time.time()
run_to_completion(sm)
end_exploration = time.time()

io = [(s.solver.eval(symbolic_input), s.posix.dumps(1)) for s in sm.deadended]
for inp, outp in io:
    print "In:  ", repr(inp)
    print "Out: ", repr(outp)

end_eval = time.time()
dump_sm_stats(sm)

print "Exploration took {} seconds, evaluation took {} seconds\nTotal runtime: {}".format(end_exploration - start, end_eval - end_exploration, end_eval - start)

