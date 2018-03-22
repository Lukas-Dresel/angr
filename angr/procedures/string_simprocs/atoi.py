import angr
import claripy
from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin
from angr.sim_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("angr.procedures.libc.atoi")


class atoi(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    def run(self, s):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch, True)

        s_addr = self.state.solver.eval_one(s)
        string = self.load_expected_string(s_addr)
        return claripy.StrToInt(string, self.state.arch.bits)
