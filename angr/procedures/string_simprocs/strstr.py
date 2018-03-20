import angr
from angr.sim_type import SimTypeString

import logging

from angr.utils.strings import load_expected_string
from claripy import StrIndexOf

l = logging.getLogger("angr.procedures.libc.strstr")

class strstr(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, haystack_addr, needle_addr, haystack_strlen=None, needle_strlen=None):
        self.argument_types = { 0: self.ty_ptr(SimTypeString()),
                                1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        str_haystack = load_expected_string(self.state, haystack_addr)
        str_needle = load_expected_string(self.state, needle_addr)
        return StrIndexOf(str_haystack, str_needle, self.state.arch.bits)
