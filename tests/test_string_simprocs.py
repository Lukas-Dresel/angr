import angr

import unittest

from claripy import StringS

from claripy import frontend_mixins, frontends, backend_manager, backends
from claripy.backends import BackendSMT_CVC4

# prep the backend for the solver to use!
backend_smt_cvc4 = backend_manager.backends._register_backend(BackendSMT_CVC4(), 'smt_cvc4', False, False)

def setup_project(binary):
    proj = angr.Project(binary, auto_load_libs=False)

    for name, simproc in angr.SIM_PROCEDURES['string_simprocs'].iteritems():
        proj.hook_symbol(name, simproc(), replace=True)

    for name, simproc in angr.SIM_PROCEDURES['cgc_strings'].iteritems():
        proj.hook_symbol(name, simproc(), replace=True)

    return proj

def make_symbolic_state(proj):
    s = proj.factory.full_init_state(add_options={angr.options.STRINGS_ANALYSIS})
    symbolic_input = StringS('input', 1000)
    s.posix.files[0].content.store(0, symbolic_input)
    return s, symbolic_input

def run_to_completion(sm):
    sm.run()
    if sm.errored:
        sm.errored[0].debug()

class TestStringOperation(unittest.TestCase):
    def test_simple(self):
        proj = setup_project('../../binaries/tests/i386/test_string_simprocs_simple')

        s, symbolic_input = make_symbolic_state(proj)
        sm = proj.factory.simulation_manager(s, save_unsat=True)

        run_to_completion(sm)

        states = [s for s in sm.deadended if 'Wow, nice job!' in s.posix.dumps(1)]
        self.assertEqual(1, len(states))

        result = states[0].solver.eval_one(symbolic_input)
        self.assertEqual('All kids take the bus, jake is in the lake', result)

    def test_fauxware(self):
        proj = setup_project('../../binaries/tests/i386/fauxware')

        s, symbolic_input = make_symbolic_state(proj)

        sm = proj.factory.simulation_manager(s, save_unsat=True)
        run_to_completion(sm)

        states = [s for s in sm.deadended if 'Welcome to the admin console, trusted user!\n' in s.posix.dumps(1)]

        for st in states:
            print st.solver.eval_upto(symbolic_input, 10)


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestStringOperation)
    unittest.TextTestRunner(verbosity=2).run(suite)
