import angr

import unittest
from angr.procedures.string_simprocs.read import read
from angr.procedures.string_simprocs.strcmp import strcmp
from angr.procedures.string_simprocs.strlen import strlen
from claripy import frontend_mixins, frontends, backend_manager, backends
from claripy.backends import BackendSMT_CVC4
from claripy.backends.backend_smt import BackendSMT

backend_smt = backend_manager.backends._register_backend(BackendSMT_CVC4(), 'smt_cvc4', False, False)

class SolverSMT(
    frontend_mixins.ConstraintFixerMixin,
    frontend_mixins.ConcreteHandlerMixin,
    frontend_mixins.ConstraintFilterMixin,
    frontend_mixins.ConstraintDeduplicatorMixin,
    frontend_mixins.EagerResolutionMixin,
    frontends.DumperFrontend
):
    def __init__(self, **kwargs):
        super(SolverSMT, self).__init__(backends.smt, **kwargs)

class TestStringOperation(unittest.TestCase):
    def test_simple(self):
        proj = angr.Project('../../binaries/tests/i386/test_string_simprocs_simple', auto_load_libs=False)
        proj.hook_symbol('read', read(), replace=True)
        proj.hook_symbol('strcmp', strcmp(), replace=True)
        proj.hook_symbol('strlen', strlen(), replace=True)

        s = proj.factory.full_init_state(add_options={angr.options.STRINGS_ANALYSIS})
        sm = proj.factory.simulation_manager(s)
        sm.run()
        if sm.errored:
            sm.errored[0].debug()
        print sm

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestStringOperation)
    unittest.TextTestRunner(verbosity=2).run(suite)
