import claripy
import angr
from angr.sim_type import SimTypeString, SimTypeLength

import logging
l = logging.getLogger("angr.procedures.libc.strlen")

class strlen(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeLength(self.state.arch)

        first_char = self.state.memory.load(s, 1)
        if first_char.op == 'Substr':
            string = first_char.args[2]
        else:
            string = first_char

        #return claripy.Extract(self.state.arch.bits - 1, 0, claripy.StrLen(string))
        return claripy.StrLen(string, self.state.arch.bits)
