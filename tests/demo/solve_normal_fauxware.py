import angr
import claripy
import time
from eval_utils import dump_sm_stats


proj = angr.Project('../../../binaries/tests/i386/fauxware')

s = proj.factory.full_init_state()
symbolic_input = claripy.BVS("input", 100 * 8)
s.posix.files[0].content.store(0, symbolic_input)
username = 'lukas'
s.solver.add(s.posix.files[0].content.load(0, 5) == claripy.BVV(username))

symbolic_file = claripy.BVS('file', 1000 * 8)
fd = s.posix.open('lukas', 0)
s.posix.files[fd].content.store(0, symbolic_file)

sm = proj.factory.simulation_manager(s)

start = time.time()
sm.run()
end_exploration = time.time()

states = [s for s in sm.deadended if 'Welcome to the admin console, trusted user!\n' in s.posix.dumps(1)]
print 'Input: ', repr(states[0].solver.eval(symbolic_input, cast_to=str))
end_eval = time.time()

dump_sm_stats(sm)

print "Exploration took {} seconds, evaluation took {} seconds\nTotal runtime: {}".format(end_exploration - start, end_eval - end_exploration, end_eval - start)
