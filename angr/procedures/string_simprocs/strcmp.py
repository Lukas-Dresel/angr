from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin

from angr.sim_type import SimTypeString, SimTypeInt
import claripy

import logging
l = logging.getLogger("angr.procedures.libc.strcmp")

class strcmp(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                       1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(32, True)

        #import ipdb; ipdb.set_trace()
        str_a = self.load_expected_string(a_addr)
        str_b = self.load_expected_string(b_addr)
        return claripy.If(str_a == str_b, claripy.BVV(0, self.state.arch.bits), claripy.BVV(1, self.state.arch.bits))
