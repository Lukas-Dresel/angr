
# prep the backend for the solver to use!
import angr
from claripy import backend_manager, StringS
from claripy.backends import BackendSMT_CVC4

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