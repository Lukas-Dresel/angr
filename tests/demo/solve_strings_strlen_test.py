import angr
import time

from claripy import Substr, StringV
from strings_helper import *
from eval_utils import dump_sm_stats


proj = setup_project('../../../binaries/tests/i386/test_string_simprocs_simple')

s, symbolic_input = make_symbolic_state(proj)

sm = proj.factory.simulation_manager(s, save_unsat=False)

start = time.time()
run_to_completion(sm)
end_exploration = time.time()

states = [s for s in sm.deadended if 'Wow' in s.posix.dumps(1)]
print repr(states[0].solver.eval(symbolic_input))
end_eval = time.time()
dump_sm_stats(sm)

print "Exploration took {} seconds, evaluation took {} seconds\nTotal runtime: {}".format(end_exploration - start, end_eval - end_exploration, end_eval - start)

