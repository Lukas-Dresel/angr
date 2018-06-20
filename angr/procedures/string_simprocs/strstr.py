import claripy
from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin, alloc_string_memory
from angr.sim_type import SimTypeString

import logging

from claripy import StrIndexOf, StrSubstr, If, BVV

l = logging.getLogger("angr.procedures.libc.strstr")

class strstr(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    # we add successors manually! NO_RET to avoid the default state being added as a successor
    NO_RET = True

    def run(self, haystack_addr, needle_addr, haystack_strlen=None, needle_strlen=None):
        self.argument_types = { 0: self.ty_ptr(SimTypeString()),
                                1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        str_haystack = self.load_expected_string(haystack_addr)
        str_needle = self.load_expected_string(needle_addr)

        index = StrIndexOf(str_haystack, str_needle, 0, self.state.arch.bits)

        failed_state = self.state.copy()
        self.constrain(failed_state, index < 0)
        self.add_ret_successor(failed_state, claripy.BVV(0, failed_state.arch.bits))

        success_state = self.state.copy()
        substr = StrSubstr(index, str_haystack.string_length, str_haystack)

        substr_ptr = alloc_string_memory(success_state, substr.string_length)
        success_state.memory.store(substr_ptr, substr)

        self.constrain(success_state, index >= 0)
        self.add_ret_successor(success_state, claripy.BVV(0, success_state.arch.bits))
