import claripy
import angr

from angr.sim_type import SimTypeString, SimTypeLength

import logging

from angr.utils.strings import try_load_as_string

l = logging.getLogger("angr.procedures.libc.strlen")

class strlen(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s_addr):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeLength(self.state.arch)

        string = try_load_as_string(self.state, s_addr)
        if string is not None:
            return claripy.StrLen(string, self.state.arch.bits)
        else:
            # if it's not handled by us, let it be handled by the normal strlen
            return angr.SIM_PROCEDURES['libc']['strlen'].ret_expr


