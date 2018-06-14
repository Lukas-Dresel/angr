from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin
from angr.sim_type import SimTypeString

import logging

from angr.utils.strings import load_expected_string
from claripy import StrIndexOf

l = logging.getLogger("angr.procedures.libc.strstr")

class strstr(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    def run(self, haystack_addr, needle_addr, haystack_strlen=None, needle_strlen=None):
        self.argument_types = { 0: self.ty_ptr(SimTypeString()),
                                1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        str_haystack = self.load_expected_string(haystack_addr)
        str_needle = self.load_expected_string(needle_addr)
        return StrIndexOf(str_haystack, str_needle, 0, self.state.arch.bits)
