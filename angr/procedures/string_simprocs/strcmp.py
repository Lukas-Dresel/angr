import angr
from angr.utils.strings import load_expected_string

from angr.sim_type import SimTypeString, SimTypeInt
import claripy

import logging
l = logging.getLogger("angr.procedures.libc.strcmp")

class strcmp(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                       1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(32, True)

        str_a = load_expected_string(self.state, a_addr)
        str_b = load_expected_string(self.state, b_addr)

        return claripy.If(str_a == str_b, claripy.BVV(0, self.state.arch.bits), claripy.BVV(1, self.state.arch.bits))
