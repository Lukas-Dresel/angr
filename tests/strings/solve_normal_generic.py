import angr
import claripy
import time
import sys
from eval_utils import dump_sm_stats


proj = angr.Project(sys.argv[1])

s = proj.factory.full_init_state()
symbolic_input = claripy.BVS("input", 100 * 8)
s.posix.files[0].content.store(0, symbolic_input)

sm = proj.factory.simulation_manager(s)

start = time.time()
sm.run()
end_exploration = time.time()

io = [(s.solver.eval(symbolic_input, cast_to=str), s.posix.dumps(1)) for s in sm.deadended]
for inp, outp in io:
    print "In:  ", repr(inp)
    print "Out: ", repr(outp)

end_eval = time.time()
dump_sm_stats(sm)

print "Exploration took {} seconds, evaluation took {} seconds\nTotal runtime: {}".format(end_exploration - start, end_eval - end_exploration, end_eval - start)
