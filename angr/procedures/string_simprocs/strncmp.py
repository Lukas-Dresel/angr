from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin
from claripy import If, StrSubstr, BVV

import logging
l = logging.getLogger("angr.procedures.libc.strncmp")


class strncmp(SimProcedure, StringSimProcedureMixin):

    def run(self, s1, s2, n):
        str_a = self.load_expected_string(s1)
        str_b = self.load_expected_string(s2)
        length = self.state.se.eval(n)
        return If(
            StrSubstr(0, length, str_a) == StrSubstr(0, length, str_b),
            BVV(0, self.state.arch.bits),
            BVV(1, self.state.arch.bits))
