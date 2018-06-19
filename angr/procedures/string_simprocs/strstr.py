from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin
from angr.sim_type import SimTypeString

import logging

from claripy import StrIndexOf, StrSubstr, If, BVV

l = logging.getLogger("angr.procedures.libc.strstr")

class strstr(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    def run(self, haystack_addr, needle_addr, haystack_strlen=None, needle_strlen=None):
        self.argument_types = { 0: self.ty_ptr(SimTypeString()),
                                1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        str_haystack = self.load_expected_string(haystack_addr)
        str_needle = self.load_expected_string(needle_addr)

        index = StrIndexOf(str_haystack, str_needle, 0, self.state.arch.bits)
        substr = StrSubstr(index, str_haystack.string_length, str_haystack)

        substr_ptr = self.alloc_string_memory(substr.string_length)
        self.state.memory.store(substr_ptr, substr)

        return If(index >= 0, substr_ptr, BVV(0, self.state.arch.bits))
