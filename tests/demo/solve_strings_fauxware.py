import angr
import time

from claripy import Substr, StringV
from strings_helper import *
from eval_utils import dump_sm_stats


proj = setup_project('../../../binaries/tests/i386/fauxware')

s, symbolic_input = make_symbolic_state(proj)

username = 'lukas'
s.solver.add(Substr(0, len(username), symbolic_input) == StringV(username))

symbolic_file = StringS('file', 1000)
fd = s.posix.open('lukas', 0)
s.posix.files[fd].content.store(0, symbolic_file)

sm = proj.factory.simulation_manager(s, save_unsat=False)

start = time.time()
run_to_completion(sm)
end_exploration = time.time()

states = [s for s in sm.deadended if 'Welcome to the admin console, trusted user!\n' in s.posix.dumps(1)]
print repr(states[0].solver.eval(symbolic_input))
end_eval = time.time()
dump_sm_stats(sm)

print "Exploration took {} seconds, evaluation took {} seconds\nTotal runtime: {}".format(end_exploration - start, end_eval - end_exploration, end_eval - start)

