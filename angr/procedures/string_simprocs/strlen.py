import claripy
import angr
from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin

from angr.sim_type import SimTypeString, SimTypeLength

import logging

l = logging.getLogger("angr.procedures.libc.strlen")

class strlen(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    def run(self, s_addr):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeLength(self.state.arch)

        string = self.try_load_string(s_addr)
        if string is not None:
            return claripy.StrLen(string, self.state.arch.bits)
        else:
            # if it's not handled by us, let it be handled by the normal strlen
            return angr.SIM_PROCEDURES['libc']['strlen'].ret_expr


