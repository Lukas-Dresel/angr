
# prep the backend for the solver to use!
import angr
import claripy
from claripy import backend_manager, StringS

backend_smt_cvc4 = backend_manager.backends.smtlib_cvc4

def setup_project(binary):
    proj = angr.Project(binary, auto_load_libs=False)

    for name, simproc in angr.SIM_PROCEDURES['string_simprocs'].iteritems():
        proj.hook_symbol(name, simproc(), replace=True)

    for name, simproc in angr.SIM_PROCEDURES['cgc_strings'].iteritems():
        proj.hook_symbol(name, simproc(), replace=True)

    return proj

def make_symbolic_state(proj):
    s = proj.factory.full_init_state(add_options={angr.options.STRINGS_ANALYSIS})
    s.solver._stored_solver = claripy.SolverStrings(backend_smt_cvc4)
    symbolic_input = StringS('input', 1000)
    s.posix.files[0].content.store(0, symbolic_input)
    return s, symbolic_input

def run_to_completion(sm):
    sm.run()
    if sm.errored:
        sm.errored[0].debug()